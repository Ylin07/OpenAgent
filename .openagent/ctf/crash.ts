import { basename, dirname, join, relative } from "node:path"
import { existsSync } from "node:fs"
import { writeFile } from "node:fs/promises"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_TIMEOUT_MS,
  clampTimeout,
  code,
  formatCommands,
  requestPermission,
  runCommand,
  section,
  selectPwnBinary,
  shellQuote,
} from "./core.ts"
import { appendRun, challengeArgs, ensureCtfWorkspace, writeNote } from "./workspace.ts"

const z = tool.schema

type OffsetHit = {
  source: string
  name: string
  value: string
  endian: "little" | "big"
  width: number
  patternOffset: number
  payloadOffset: number
}

function pyString(value: string) {
  return JSON.stringify(value)
}

function cyclicProgram(length: number, wordSize: number) {
  return [
    "from pwn import *",
    "import sys",
    "context.log_level = 'error'",
    `sys.stdout.buffer.write(cyclic(${length}, n=${wordSize}))`,
  ].join("; ")
}

async function inferWordSize(binary: string, timeoutMs: number) {
  const result = await runCommand(dirname(binary), {
    label: "infer word size",
    command: ["file", "-b", binary],
    timeoutMs,
    maxOutput: 2_000,
  })
  return /64-bit/i.test(result.stdout) ? 8 : 4
}

function marker(name: string) {
  return `--- ctf_crash ${name} ---`
}

function buildGdbScript(input: {
  delivery: "stdin" | "argv"
  inputPath?: string
  wordSize: number
  stackWords: number
}) {
  const stackFormat = input.wordSize >= 8 ? "gx" : "wx"
  const runLine = input.delivery === "stdin" ? `run < ${shellQuote(input.inputPath ?? "")}` : "run"
  return [
    "set pagination off",
    "set confirm off",
    "set disassembly-flavor intel",
    "handle SIGALRM nostop noprint pass",
    runLine,
    `printf "\\n${marker("signal")}\\n"`,
    "info program",
    `printf "\\n${marker("registers")}\\n"`,
    "info registers",
    `printf "\\n${marker("pc")}\\n"`,
    "x/16i $pc",
    `printf "\\n${marker("stack")}\\n"`,
    `x/${input.stackWords}${stackFormat} $sp`,
    `printf "\\n${marker("backtrace")}\\n"`,
    "bt",
    "",
  ].join("\n")
}

function sectionName(line: string, current: string) {
  if (line.includes(marker("registers"))) return "registers"
  if (line.includes(marker("stack"))) return "stack"
  if (line.includes(marker("backtrace"))) return "backtrace"
  if (line.includes(marker("pc"))) return "pc"
  if (line.includes(marker("signal"))) return "signal"
  return current
}

function collectCandidates(gdbText: string) {
  const candidates: Array<{ source: string; name: string; value: string }> = []
  let current = "output"
  let stackIndex = 0

  for (const line of gdbText.split("\n")) {
    current = sectionName(line, current)
    if (current === "registers") {
      const match = line.match(/^\s*([A-Za-z][A-Za-z0-9_]*)\s+(0x[0-9A-Fa-f]+)/)
      if (match) candidates.push({ source: "register", name: match[1], value: match[2] })
      continue
    }
    if (current === "stack") {
      const body = line.includes(":") ? line.slice(line.indexOf(":") + 1) : line
      const values = body.match(/0x[0-9A-Fa-f]+/g) ?? []
      values.forEach((value) => candidates.push({ source: "stack", name: `word${stackIndex++}`, value }))
    }
  }

  return candidates
}

function hexToBuffer(value: string) {
  let hex = value.replace(/^0x/i, "")
  if (!hex || /^0+$/.test(hex)) return Buffer.alloc(0)
  if (hex.length % 2) hex = `0${hex}`
  return Buffer.from(hex, "hex")
}

function candidateChunks(value: string, wordSize: number) {
  const be = hexToBuffer(value)
  if (!be.length) return []
  const le = Buffer.from(be).reverse()
  const widths = Array.from(new Set([wordSize, 8, 4])).filter((width) => width > 0)
  const chunks: Array<{ endian: "little" | "big"; width: number; bytes: Buffer }> = []

  for (const [endian, bytes] of [
    ["little", le],
    ["big", be],
  ] as const) {
    for (const width of widths) {
      if (bytes.length >= width) chunks.push({ endian, width, bytes: bytes.subarray(0, width) })
    }
  }
  return chunks
}

function findOffsets(pattern: string, candidates: Array<{ source: string; name: string; value: string }>, wordSize: number, prefixLength: number) {
  const patternBytes = Buffer.from(pattern, "binary")
  const hits: OffsetHit[] = []
  const seen = new Set<string>()

  for (const candidate of candidates) {
    for (const chunk of candidateChunks(candidate.value, wordSize)) {
      const offset = patternBytes.indexOf(chunk.bytes)
      if (offset < 0) continue
      const key = `${candidate.source}:${candidate.name}:${candidate.value}:${chunk.endian}:${chunk.width}:${offset}`
      if (seen.has(key)) continue
      seen.add(key)
      hits.push({
        source: candidate.source,
        name: candidate.name,
        value: candidate.value,
        endian: chunk.endian,
        width: chunk.width,
        patternOffset: offset,
        payloadOffset: prefixLength + offset,
      })
    }
  }

  const rank = (hit: OffsetHit) => {
    const name = hit.name.toLowerCase()
    let value = 40
    if (hit.source === "register" && ["rip", "eip", "pc"].includes(name)) value = 0
    else if (hit.source === "stack" && name === "word0") value = 5
    else if (hit.source === "stack") value = 10
    else if (hit.source === "register" && ["rbp", "ebp"].includes(name)) value = 20
    else if (hit.source === "register") value = 25
    if (hit.endian !== "little") value += 4
    if (hit.width < wordSize) value += 12
    return value
  }

  return hits.sort((a, b) => rank(a) - rank(b) || a.patternOffset - b.patternOffset).slice(0, 40)
}

function ripHijackHit(hits: OffsetHit[]) {
  return (
    hits.find((hit) => hit.source === "stack" && hit.name === "word0" && hit.endian === "little") ??
    hits.find((hit) => hit.source === "stack" && hit.name === "word0") ??
    hits[0]
  )
}

function formatHits(hits: OffsetHit[], limit = 12) {
  if (!hits.length) return "未在寄存器或栈快照中匹配到 cyclic 片段。检查输入路径、patternLength、wordSize，或目标是否没有崩溃到可控返回地址。"
  const hijack = ripHijackHit(hits)
  const shown = hits.slice(0, limit)
  const omitted = hits.length - shown.length
  return [
    hijack ? `>>> RIP hijack offset = ${hijack.payloadOffset} <<< (${hijack.source}.${hijack.name}, pattern_offset=${hijack.patternOffset})` : "",
    ...shown.map((hit) =>
      [
        `- ${hit.source}.${hit.name}=${hit.value}`,
        `pattern_offset=${hit.patternOffset}`,
        `payload_offset=${hit.payloadOffset}`,
        `match=${hit.endian}/${hit.width}B`,
      ].join(" "),
    ),
    omitted > 0 ? `- ... ${omitted} more lower-priority matches omitted` : "",
  ].filter(Boolean).join("\n")
}

export const crash = tool({
  description:
    "CTF pwn crash 自动化：生成 pwntools cyclic，gdb batch 运行，收集 registers/stack/backtrace，并自动从寄存器和栈里定位 offset。",
  args: {
    binary: z.string().optional().describe("ELF binary 路径，相对 session directory；省略时自动在目录内选择 ELF"),
    python: z.string().optional().describe("Python 解释器，默认 python3"),
    gdb: z.string().optional().describe("gdb 可执行文件，默认 gdb"),
    argv: z.array(z.string()).optional().describe("传给目标程序的 argv；delivery=argv 时可用 {pattern} 占位"),
    delivery: z.enum(["stdin", "argv"]).optional().describe("payload 投递方式，默认 stdin；argv 模式无占位时把 pattern 追加为最后一个参数"),
    prefix: z.string().max(8192).optional().describe("cyclic 前缀，用于菜单/命令前置输入"),
    suffix: z.string().max(8192).optional().describe("cyclic 后缀"),
    appendNewline: z.boolean().optional().describe("delivery=stdin 时是否追加换行，默认 true"),
    patternLength: z.number().int().positive().max(200000).optional().describe("cyclic 长度，默认 1024"),
    wordSize: z.number().int().min(1).max(16).optional().describe("pwntools cyclic n；默认按 ELF 32/64-bit 推断为 4/8"),
    stackWords: z.number().int().positive().max(256).optional().describe("gdb 栈快照 word 数，默认 64"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const binary = await selectPwnBinary(args.binary, ctx)
    if (!existsSync(binary)) throw new Error(`Binary not found: ${binary}`)
    const cwd = dirname(binary)
    const timeoutMs = clampTimeout(args.timeoutMs)
    const python = args.python?.trim() || "python3"
    const gdb = args.gdb?.trim() || "gdb"
    const delivery = args.delivery ?? "stdin"
    const patternLength = args.patternLength ?? 1024
    const wordSize = args.wordSize ?? (await inferWordSize(binary, timeoutMs))
    const stackWords = args.stackWords ?? 64
    const prefix = args.prefix ?? ""
    const suffix = args.suffix ?? ""
    const appendNewline = args.appendNewline ?? true

    await requestPermission(ctx, "ctf_crash", binary, {
      binary,
      delivery,
      patternLength,
      wordSize,
    })
    ctx.metadata({ title: `CTF crash: ${basename(binary)}`, metadata: { binary, delivery, patternLength, wordSize } })

    const patternResult = await runCommand(cwd, {
      label: "pwntools cyclic",
      command: [python, "-c", cyclicProgram(patternLength, wordSize)],
      timeoutMs,
      maxOutput: patternLength + 1024,
    })
    if (patternResult.exitCode !== 0 || !patternResult.stdout.length) {
      return {
        title: "CTF crash: cyclic failed",
        output: section("cyclic 生成失败", formatCommands([patternResult])),
        metadata: { binary, exitCode: patternResult.exitCode },
      }
    }

    const ws = await ensureCtfWorkspace(ctx, args.challenge)
    const stamp = Date.now()
    const pattern = patternResult.stdout
    const payloadCore = `${prefix}${pattern}${suffix}`
    const inputPath = join(ws.artifacts, `crash-${basename(binary)}-${stamp}.in`)
    const scriptPath = join(ws.artifacts, `crash-${basename(binary)}-${stamp}.gdb`)
    const outputPath = join(ws.artifacts, `crash-${basename(binary)}-${stamp}.txt`)

    let runArgv = args.argv ?? []
    if (delivery === "argv") {
      const hasPlaceholder = runArgv.some((item) => item.includes("{pattern}"))
      runArgv = hasPlaceholder ? runArgv.map((item) => item.replaceAll("{pattern}", payloadCore)) : [...runArgv, payloadCore]
    } else {
      await writeFile(inputPath, payloadCore + (appendNewline ? "\n" : ""))
    }

    const gdbScript = buildGdbScript({
      delivery,
      inputPath,
      wordSize,
      stackWords,
    })
    await writeFile(scriptPath, gdbScript)

    const gdbResult = await runCommand(cwd, {
      label: "gdb batch crash",
      command: [gdb, "-q", "--batch", "-x", scriptPath, "--args", binary, ...runArgv],
      timeoutMs,
      maxOutput: 80_000,
    })
    const gdbText = [gdbResult.stdout, gdbResult.stderr].filter(Boolean).join("\n")
    await writeFile(
      outputPath,
      [
        `$ ${gdbResult.command}`,
        `exit=${gdbResult.exitCode ?? "?"}${gdbResult.timedOut ? " timeout=true" : ""}`,
        "",
        gdbText,
      ].join("\n"),
    )

    const prefixLength = Buffer.from(prefix, "binary").length
    const hits = findOffsets(pattern, collectCandidates(gdbText), wordSize, prefixLength)
    const best = ripHijackHit(hits)

    await appendRun(
      ctx,
      {
        type: "crash",
        binary,
        delivery,
        patternLength,
        wordSize,
        offset: best?.payloadOffset,
        patternOffset: best?.patternOffset,
        artifacts: { inputPath: delivery === "stdin" ? inputPath : undefined, scriptPath, outputPath },
        exitCode: gdbResult.exitCode,
        timedOut: gdbResult.timedOut,
      },
      args.challenge,
    )
    await writeNote(ctx, {
      category: "pwn",
      title: `Crash offset ${basename(binary)}`,
      content: `binary: ${binary}\ndelivery: ${delivery}\nwordSize: ${wordSize}\npatternLength: ${patternLength}`,
      evidence: formatHits(hits),
      next: best
        ? `用 payload_offset=${best.payloadOffset} 构造下一阶段 payload，并用 gdb/pwntools 复测控制流。`
        : "调整输入投递方式或 pattern 参数后重跑 ctf_crash。",
      tags: ["pwn", "crash", basename(binary)],
      challenge: args.challenge,
    })

    return {
      title: `CTF crash: ${relative(ctx.worktree, binary) || binary}`,
      output: [
        section("目标", [`binary: ${binary}`, `delivery: ${delivery}`, `wordSize: ${wordSize}`, `patternLength: ${patternLength}`]),
        section("Offset 候选", formatHits(hits)),
        section(
          "Artifacts",
          [
            delivery === "stdin" ? `input: ${relative(ctx.worktree, inputPath) || inputPath}` : "",
            `gdb-script: ${relative(ctx.worktree, scriptPath) || scriptPath}`,
            `gdb-output: ${relative(ctx.worktree, outputPath) || outputPath}`,
          ],
        ),
        section("GDB batch 摘要", formatCommands([gdbResult])),
        section("cyclic 命令", code(`${python} -c ${pyString(cyclicProgram(patternLength, wordSize))}`)),
      ].join("\n"),
      metadata: {
        binary,
        delivery,
        wordSize,
        patternLength,
        offset: best?.payloadOffset,
        patternOffset: best?.patternOffset,
        artifacts: { inputPath: delivery === "stdin" ? inputPath : undefined, scriptPath, outputPath },
      },
    }
  },
})
