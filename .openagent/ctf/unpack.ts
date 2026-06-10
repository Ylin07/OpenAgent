import { basename, dirname, join, relative } from "node:path"
import { stat, readFile, writeFile } from "node:fs/promises"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_FILE_READ,
  MAX_TIMEOUT_MS,
  clampTimeout,
  code,
  formatCommands,
  normalizePath,
  requestPermission,
  runBatch,
  runCommand,
  section,
  shellQuote,
} from "./core.ts"
import { appendRun, ensureCtfWorkspace, writeNote } from "./workspace.ts"

const z = tool.schema

type SectionEntropy = {
  name: string
  offset: number
  size: number
  entropy: number
}

function entropy(buffer: Buffer) {
  if (!buffer.length) return 0
  const counts = new Array<number>(256).fill(0)
  for (const byte of buffer) counts[byte]++
  let value = 0
  for (const count of counts) {
    if (!count) continue
    const p = count / buffer.length
    value -= p * Math.log2(p)
  }
  return value
}

async function readEntropySample(path: string) {
  const info = await stat(path)
  const data = await readFile(path)
  return data.subarray(0, Math.min(data.length, Math.min(info.size, MAX_FILE_READ)))
}

function parseReadelfSections(text: string) {
  const sections: Array<{ name: string; offset: number; size: number }> = []
  for (const line of text.split("\n")) {
    const match = line.match(/^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9A-Fa-f]+\s+([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)/)
    if (!match) continue
    sections.push({
      name: match[1],
      offset: Number.parseInt(match[2], 16),
      size: Number.parseInt(match[3], 16),
    })
  }
  return sections
}

async function sectionEntropies(path: string, readelfOutput: string) {
  const file = await readFile(path)
  return parseReadelfSections(readelfOutput)
    .filter((item) => item.size > 0 && item.offset >= 0 && item.offset + item.size <= file.length)
    .map((item): SectionEntropy => ({
      ...item,
      entropy: entropy(file.subarray(item.offset, item.offset + item.size)),
    }))
    .sort((a, b) => b.entropy - a.entropy)
    .slice(0, 24)
}

function formatEntropy(fileEntropy: number, sections: SectionEntropy[]) {
  const rows = [`file_entropy=${fileEntropy.toFixed(3)}`]
  for (const item of sections) {
    rows.push(`- ${item.name} off=0x${item.offset.toString(16)} size=0x${item.size.toString(16)} entropy=${item.entropy.toFixed(3)}`)
  }
  return rows.join("\n")
}

function packerHints(input: {
  fileOutput: string
  stringsOutput: string
  sectionsOutput: string
  upxOutput: string
  fileEntropy: number
  sections: SectionEntropy[]
}) {
  const binaryHaystack = [input.fileOutput, input.stringsOutput, input.sectionsOutput].join("\n")
  const hints: string[] = []
  if (
    /UPX!|UPX0|UPX1|UPX2|packed with UPX/i.test(binaryHaystack) ||
    /tested\s+ok|Packed data is corrupt|CantUnpackException|can.t be unpacked/i.test(input.upxOutput)
  ) {
    hints.push("UPX signature/string 或 upx -t packed 结果命中")
  }
  if (/\b(?:Themida|VMProtect|ASPack|MPRESS|PECompact|Enigma|Obsidium)\b/.test(binaryHaystack)) {
    hints.push("常见商业/PE 壳字符串命中")
  }
  if (/\.upx|UPX0|UPX1|\.aspack|\.vmp|\.themida/i.test(input.sectionsOutput)) hints.push("section name 命中壳特征")
  if (input.fileEntropy >= 7.1) hints.push(`整体熵偏高 (${input.fileEntropy.toFixed(3)})`)
  const highSections = input.sections.filter((item) => item.size >= 0x200 && item.entropy >= 7.2)
  if (highSections.length) hints.push(`高熵 section: ${highSections.map((item) => `${item.name}:${item.entropy.toFixed(2)}`).join(", ")}`)
  if (/not packed by UPX|NotPackedException/i.test(input.upxOutput)) hints.push("upx -t: not packed")
  return hints.length ? hints.join("\n") : "未命中明显壳特征；仍需结合入口点、imports、section 权限和动态行为判断。"
}

function validateAddress(value: string | undefined, name: string) {
  if (!value) return undefined
  if (!/^0x[0-9A-Fa-f]+$/.test(value.trim())) throw new Error(`${name} 必须是十六进制地址，例如 0x401000`)
  return value.trim()
}

function safeArtifactName(input: string | undefined, fallback: string) {
  const raw = input?.trim() || fallback
  return basename(raw).replace(/[^A-Za-z0-9_.-]/g, "_")
}

function validateGdbCommands(commands: string[] | undefined) {
  const list = commands ?? []
  if (list.length > 40) throw new Error("gdbCommands 最多 40 条")
  for (const command of list) {
    if (/^\s*(shell|pipe|make)\b/i.test(command)) {
      throw new Error(`禁止在 ctf_unpack gdbCommands 中使用 gdb shell-like 命令: ${command}`)
    }
  }
  return list
}

function marker(name: string) {
  return `--- ctf_unpack ${name} ---`
}

function buildDumpScript(input: {
  mode: "starti" | "run"
  gdbCommands: string[]
  dumpStart?: string
  dumpEnd?: string
  dumpPath?: string
}) {
  const lines = [
    "set pagination off",
    "set confirm off",
    "set disassembly-flavor intel",
    input.mode === "run" ? "run" : "starti",
    ...input.gdbCommands,
    `printf "\\n${marker("files")}\\n"`,
    "info files",
    `printf "\\n${marker("mappings")}\\n"`,
    "info proc mappings",
    `printf "\\n${marker("registers")}\\n"`,
    "info registers",
    `printf "\\n${marker("pc")}\\n"`,
    "x/24i $pc",
    `printf "\\n${marker("backtrace")}\\n"`,
    "bt",
  ]
  if (input.dumpStart && input.dumpEnd && input.dumpPath) {
    lines.push(`dump memory ${shellQuote(input.dumpPath)} ${input.dumpStart} ${input.dumpEnd}`)
  }
  lines.push("")
  return lines.join("\n")
}

export const unpack = tool({
  description:
    "CTF unpack 工具：识别壳/高熵/UPX，受控 UPX unpack 到 artifact，gdb batch 记录 OEP/mappings/registers/IAT-GOT，并支持指定范围 memory dump。",
  args: {
    action: z.enum(["identify", "upx", "dump"]).describe("identify=识别，upx=UPX 解包到 artifact，dump=gdb 受控动态记录/内存 dump"),
    target: z.string().optional().describe("目标文件路径，相对 session directory；默认当前目录"),
    output: z.string().optional().describe("action=upx 的输出文件名或 action=dump 的 dump 文件名"),
    gdb: z.string().optional().describe("gdb 可执行文件，默认 gdb"),
    runArgs: z.array(z.string()).optional().describe("action=dump 时传给程序的 argv"),
    mode: z.enum(["starti", "run"]).optional().describe("action=dump 的启动方式，默认 starti"),
    gdbCommands: z.array(z.string()).optional().describe("action=dump 中 starti/run 后追加的 gdb 命令，如 break/continue/set"),
    dumpStart: z.string().optional().describe("action=dump 可选内存 dump 起始地址，必须是 0x..."),
    dumpEnd: z.string().optional().describe("action=dump 可选内存 dump 结束地址，必须是 0x..."),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const target = normalizePath(args.target, ctx)
    const timeoutMs = clampTimeout(args.timeoutMs)
    const cwd = dirname(target)
    const ws = await ensureCtfWorkspace(ctx)

    await requestPermission(ctx, "ctf_unpack", target, { action: args.action, target })
    ctx.metadata({ title: `CTF unpack: ${basename(target)}`, metadata: { action: args.action, target } })

    if (args.action === "identify") {
      const results = await runBatch(cwd, [
        { label: "file", command: ["file", "-b", target], timeoutMs, maxOutput: 4_000 },
        { label: "upx test", command: ["upx", "-t", target], timeoutMs, maxOutput: 8_000 },
        { label: "readelf header", command: ["readelf", "-h", target], timeoutMs, maxOutput: 12_000 },
        { label: "readelf sections", command: ["readelf", "-SW", target], timeoutMs, maxOutput: 30_000 },
        { label: "objdump private headers", command: ["objdump", "-p", target], timeoutMs, maxOutput: 30_000 },
        { label: "strings", command: ["strings", "-a", "-n", "4", target], timeoutMs, maxOutput: 40_000 },
      ])
      const sample = await readEntropySample(target)
      const fileEntropy = entropy(sample)
      const readelfSections = results.find((item) => item.label === "readelf sections")?.stdout ?? ""
      const sections = await sectionEntropies(target, readelfSections).catch(() => [])
      const stringsOutput = results.find((item) => item.label === "strings")?.stdout ?? ""
      const stringHints = stringsOutput
        .split("\n")
        .filter((line) => /UPX|UPX!|packed|packer|Themida|VMProtect|ASPack|MPRESS|IAT|OEP|anti|debug/i.test(line))
        .slice(0, 80)
        .join("\n")
      const hints = packerHints({
        fileOutput: results.find((item) => item.label === "file")?.stdout ?? "",
        stringsOutput: stringHints,
        sectionsOutput: readelfSections,
        upxOutput: [results.find((item) => item.label === "upx test")?.stdout, results.find((item) => item.label === "upx test")?.stderr]
          .filter(Boolean)
          .join("\n"),
        fileEntropy,
        sections,
      })

      await appendRun(ctx, { type: "unpack", action: "identify", target, fileEntropy, hints })
      const likelyUpx = /UPX signature|string 或 upx -t packed|UPX-like/i.test(hints)
      await writeNote(ctx, {
        category: "reverse",
        title: `Unpack identify ${basename(target)}`,
        content: `target: ${target}`,
        evidence: [`Hints:\n${hints}`, `Entropy:\n${formatEntropy(fileEntropy, sections)}`, stringHints ? `Strings:\n${stringHints}` : ""]
          .filter(Boolean)
          .join("\n\n"),
        next: likelyUpx
          ? "如确认是 UPX，使用 ctf_unpack action=upx 生成解包副本。"
          : "若静态入口/import 异常，使用 ctf_unpack action=dump 在 starti/OEP 附近记录 mappings/registers，必要时指定 dumpStart/dumpEnd。",
        tags: ["reverse", "unpack", basename(target)],
      })

      return {
        title: `CTF unpack identify: ${relative(ctx.worktree, target) || target}`,
        output: [
          section("目标", target),
          section("壳/熵判断", hints),
          section("Entropy", formatEntropy(fileEntropy, sections)),
          section("可疑字符串", stringHints || "未命中默认 packer 字符串。"),
          section("命令摘要", formatCommands(results.map((item) => ({ ...item, stdout: item.stdout.slice(0, 4_000) })))),
        ].join("\n"),
        metadata: { action: args.action, target, fileEntropy, hints },
      }
    }

    if (args.action === "upx") {
      const output = args.output
        ? normalizePath(args.output, ctx)
        : join(ws.artifacts, `${safeArtifactName(basename(target), "chall")}.upx-unpacked`)
      await requestPermission(ctx, "ctf_unpack", output, { action: args.action, target, output })
      const results = await runBatch(cwd, [
        { label: "upx test", command: ["upx", "-t", target], timeoutMs, maxOutput: 8_000 },
        { label: "upx decompress", command: ["upx", "-d", "-o", output, target], timeoutMs, maxOutput: 20_000 },
        { label: "file unpacked", command: ["file", "-b", output], timeoutMs, maxOutput: 4_000 },
        { label: "readelf unpacked header", command: ["readelf", "-h", output], timeoutMs, maxOutput: 12_000 },
      ])
      await appendRun(ctx, {
        type: "unpack",
        action: "upx",
        target,
        output,
        exitCode: results.find((item) => item.label === "upx decompress")?.exitCode,
      })
      await writeNote(ctx, {
        category: "reverse",
        title: `UPX unpack ${basename(target)}`,
        content: `target: ${target}\noutput: ${output}`,
        evidence: formatCommands(results),
        next: "对解包副本重新跑 ctf_reverse/ctf_pwn，确认入口点、imports 和字符串是否恢复。",
        tags: ["reverse", "unpack", "upx", basename(target)],
      })

      return {
        title: `CTF UPX unpack: ${relative(ctx.worktree, output) || output}`,
        output: [section("输出", output), section("命令结果", formatCommands(results))].join("\n"),
        metadata: { action: args.action, target, output },
      }
    }

    const gdb = args.gdb?.trim() || "gdb"
    const mode = args.mode ?? "starti"
    const gdbCommands = validateGdbCommands(args.gdbCommands)
    const dumpStart = validateAddress(args.dumpStart, "dumpStart")
    const dumpEnd = validateAddress(args.dumpEnd, "dumpEnd")
    if ((dumpStart && !dumpEnd) || (!dumpStart && dumpEnd)) throw new Error("dumpStart 和 dumpEnd 必须同时提供")

    const stamp = Date.now()
    const dumpPath = dumpStart && dumpEnd ? join(ws.artifacts, safeArtifactName(args.output, `mem-${basename(target)}-${stamp}.bin`)) : undefined
    const scriptPath = join(ws.artifacts, `unpack-dump-${basename(target)}-${stamp}.gdb`)
    const outputPath = join(ws.artifacts, `unpack-dump-${basename(target)}-${stamp}.txt`)
    if (dumpPath) await requestPermission(ctx, "ctf_unpack", dumpPath, { action: args.action, target, dumpPath, dumpStart, dumpEnd })
    const script = buildDumpScript({ mode, gdbCommands, dumpStart, dumpEnd, dumpPath })
    await writeFile(scriptPath, script)

    const gdbResult = await runCommand(cwd, {
      label: "gdb unpack dump",
      command: [gdb, "-q", "--batch", "-x", scriptPath, "--args", target, ...(args.runArgs ?? [])],
      timeoutMs,
      maxOutput: 100_000,
    })
    const importResults = await runBatch(cwd, [
      { label: "readelf relocations", command: ["readelf", "-r", target], timeoutMs, maxOutput: 30_000 },
      { label: "objdump dynamic relocations", command: ["objdump", "-R", target], timeoutMs, maxOutput: 30_000 },
      { label: "objdump private headers", command: ["objdump", "-p", target], timeoutMs, maxOutput: 30_000 },
    ])
    await writeFile(
      outputPath,
      [
        `$ ${gdbResult.command}`,
        `exit=${gdbResult.exitCode ?? "?"}${gdbResult.timedOut ? " timeout=true" : ""}`,
        "",
        gdbResult.stdout,
        gdbResult.stderr,
        "",
        "## Import/IAT/GOT commands",
        formatCommands(importResults),
      ].join("\n"),
    )

    await appendRun(ctx, {
      type: "unpack",
      action: "dump",
      target,
      mode,
      scriptPath,
      outputPath,
      dumpPath,
      dumpStart,
      dumpEnd,
      exitCode: gdbResult.exitCode,
      timedOut: gdbResult.timedOut,
    })
    await writeNote(ctx, {
      category: "reverse",
      title: `Unpack dump ${basename(target)}`,
      content: [
        `target: ${target}`,
        `mode: ${mode}`,
        `gdb-script: ${scriptPath}`,
        `gdb-output: ${outputPath}`,
        dumpPath ? `memory-dump: ${dumpPath}` : "",
      ].filter(Boolean).join("\n"),
      evidence: [
        "OEP/PC/mappings/registers 已记录在 gdb-output artifact。",
        dumpPath ? `dump range: ${dumpStart}-${dumpEnd}` : "未指定 dumpStart/dumpEnd，因此只记录动态状态，不 dump 内存。",
      ].join("\n"),
      next: "根据 mappings 和 $pc 判断 OEP；如果已到解包后代码区，指定可执行映射范围重跑 dump 并导入 IDA/Ghidra/r2。",
      tags: ["reverse", "unpack", "dump", basename(target)],
    })

    return {
      title: `CTF unpack dump: ${relative(ctx.worktree, target) || target}`,
      output: [
        section("目标", [`target: ${target}`, `mode: ${mode}`]),
        section(
          "Artifacts",
          [
            `gdb-script: ${relative(ctx.worktree, scriptPath) || scriptPath}`,
            `gdb-output: ${relative(ctx.worktree, outputPath) || outputPath}`,
            dumpPath ? `memory-dump: ${relative(ctx.worktree, dumpPath) || dumpPath}` : "",
          ],
        ),
        section("GDB 摘要", formatCommands([gdbResult])),
        section("IAT/GOT/Reloc 摘要", formatCommands(importResults.map((item) => ({ ...item, stdout: item.stdout.slice(0, 4_000) })))),
        section("复现", code(`${gdb} -q --batch -x ${shellQuote(scriptPath)} --args ${shellQuote(target)}`)),
      ].join("\n"),
      metadata: { action: args.action, target, mode, scriptPath, outputPath, dumpPath },
    }
  },
})
