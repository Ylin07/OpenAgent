import { basename, dirname, relative } from "node:path"
import { existsSync } from "node:fs"
import { Socket } from "node:net"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_TIMEOUT_MS,
  clampTimeout,
  code,
  formatCommands,
  requestPermission,
  runBatch,
  section,
  selectPwnBinary,
  type CommandSpec,
} from "./core.ts"
import { appendRun, challengeArgs, updateCtfState, writeNote } from "./workspace.ts"

const z = tool.schema

type RequiredDoc = {
  domain: "pwn"
  topic: "index" | "stack-rop" | "format-string" | "heap-fsop" | "advanced"
  reason: string
}

export const pwn = tool({
  description:
    "CTF pwn 工具：ELF/pwn triage，收集保护、架构、符号、导入、字符串、可选 deep 可疑函数摘要、本地 smoke run 和授权远程 banner。",
  args: {
    binary: z.string().optional().describe("ELF binary 路径，相对 session directory"),
    deep: z.boolean().optional().describe("启用轻量 deep 扫描：用 objdump 汇总调用危险函数的函数和栈变量来源"),
    runInput: z.string().max(4096).optional().describe("可选本地 smoke run stdin"),
    remoteHost: z.string().optional().describe("授权 CTF 远程 host，仅做 banner check"),
    remotePort: z.number().int().positive().max(65535).optional(),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const binary = await selectPwnBinary(args.binary, ctx)
    await requestPermission(ctx, "ctf_pwn", binary, {
      binary,
      remoteHost: args.remoteHost,
      remotePort: args.remotePort,
    })
    if ((args.remoteHost && !args.remotePort) || (!args.remoteHost && args.remotePort)) {
      throw new Error("remoteHost 和 remotePort 必须同时提供")
    }
    if (args.remoteHost && args.remotePort) {
      await requestPermission(ctx, "ctf_pwn", `${args.remoteHost}:${args.remotePort}`, {
        remoteHost: args.remoteHost,
        remotePort: args.remotePort,
      })
    }
    ctx.metadata({ title: `CTF pwn: ${basename(binary)}`, metadata: { binary } })

    if (!existsSync(binary)) throw new Error(`Binary not found: ${binary}`)
    const cwd = dirname(binary)
    const timeoutMs = clampTimeout(args.timeoutMs)
    const commands: CommandSpec[] = [
      { label: "file", command: ["file", "-b", binary], timeoutMs },
      { label: "checksec", command: ["checksec", "--file", binary], timeoutMs },
      { label: "readelf header", command: ["readelf", "-h", binary], timeoutMs },
      { label: "readelf program headers", command: ["readelf", "-l", binary], timeoutMs },
      { label: "readelf symbols", command: ["readelf", "-Ws", binary], timeoutMs },
      { label: "imports", command: ["objdump", "-T", binary], timeoutMs },
      { label: "strings pwn hints", command: ["strings", "-a", "-n", "4", binary], timeoutMs },
    ]
    if (args.deep) {
      commands.push({
        label: "deep objdump disassembly",
        command: ["objdump", "-d", "-Mintel", binary],
        timeoutMs,
        maxOutput: 160_000,
      })
    }
    if (args.runInput !== undefined) {
      commands.push({ label: "local smoke run", command: [binary], input: args.runInput, timeoutMs })
    }
    const results = await runBatch(cwd, commands)
    const banner =
      args.remoteHost && args.remotePort
        ? await remoteBanner(args.remoteHost, args.remotePort, timeoutMs).catch((error) => `remote error: ${String(error)}`)
        : ""
    const imports = results.find((item) => item.label === "imports")?.stdout ?? ""
    const risky = imports
      .split("\n")
      .filter((line) => /gets|scanf|strcpy|strcat|sprintf|read|recv|system|mprotect|printf|puts|malloc|free/i.test(line))
      .slice(0, 80)
      .join("\n")
    const strings = results.find((item) => item.label === "strings pwn hints")?.stdout ?? ""
    const stringHints = strings
      .split("\n")
      .filter((line) => /%p|%s|%x|flag|sh|bin\/sh|password|overflow|admin|debug|canary|libc/i.test(line))
      .slice(0, 80)
      .join("\n")
    const deepText = args.deep
      ? summarizeDeepPwn(results.find((item) => item.label === "deep objdump disassembly")?.stdout ?? "")
      : ""
    const commandText = formatCommands(results.filter((item) => item.label !== "deep objdump disassembly"))
    const requiredDocs = recommendPwnDocs({ risky, stringHints, deepText, banner, imports, strings })

    await appendRun(
      ctx,
      {
        type: "pwn",
        binary,
        remote: args.remoteHost && args.remotePort ? `${args.remoteHost}:${args.remotePort}` : undefined,
        requiredDocs,
      },
      args.challenge,
    )
    await updateCtfState(
      ctx,
      (state) => {
        state.requiredDocs = {
          ...(state.requiredDocs && typeof state.requiredDocs === "object" && !Array.isArray(state.requiredDocs)
            ? state.requiredDocs
            : {}),
          pwn: requiredDocs.map((item) => ({
            ...item,
            source: "ctf_pwn",
            binary,
            createdAt: new Date().toISOString(),
          })),
        }
        return state
      },
      args.challenge,
    )
    await writeNote(ctx, {
      category: "pwn",
      title: `Pwn triage ${basename(binary)}`,
      content: `binary: ${binary}`,
      evidence: [risky ? `Risky imports:\n${risky}` : "", stringHints ? `Interesting strings:\n${stringHints}` : ""]
        .filter(Boolean)
        .join("\n\n"),
      next: args.deep
        ? `先调用 ctf_doc 读取 required docs，再验证 deep 摘要里的危险调用点；如可控崩溃，生成 cyclic 并定位 offset。`
        : `先调用 ctf_doc 读取 required docs，再确认输入面和 crash primitive；如可控崩溃，生成 cyclic 并定位 offset。可用 deep=true 直接摘要可疑函数。`,
      tags: ["pwn", basename(binary)],
      challenge: args.challenge,
    })

    return {
      title: `CTF pwn: ${relative(ctx.worktree, binary) || binary}`,
      output: [
        section("目标", binary),
        section("Binary triage", commandText),
        section("危险导入", risky || "默认 hint 列表未命中常见危险导入。"),
        args.deep ? section("Deep 可疑函数摘要", deepText || "未在反汇编中识别到直接危险调用点。") : "",
        section("可疑字符串", stringHints || "默认 hint 列表未命中常见 pwn 字符串。"),
        banner ? section("Remote banner", code(banner)) : "",
        section("Required docs", formatRequiredDocs(requiredDocs)),
        section("下一步", [
          "- 先调用上面 Required docs 对应的 ctf_doc，确认文档清单已进入 .ctf/state.json。",
          args.deep ? "- 优先复核 Deep 摘要命中的函数，通常无需再手动反编译同一调用链。" : "",
          "- 用 cyclic pattern 验证 crash 和 offset。",
          "- 根据 NX/PIE/canary/RELRO 决定 ret2win、ret2libc、ROP、format string、heap 或逻辑路径。",
          "- 本地 exploit 稳定后再测试授权远程服务。",
        ]),
      ].join("\n"),
      metadata: { binary, remote: args.remoteHost && args.remotePort ? `${args.remoteHost}:${args.remotePort}` : undefined },
    }
  },
})

function recommendPwnDocs(input: {
  risky: string
  stringHints: string
  deepText: string
  banner: string
  imports: string
  strings: string
}): RequiredDoc[] {
  const haystack = [input.risky, input.stringHints, input.deepText, input.banner, input.imports, input.strings].join("\n")
  const docs: RequiredDoc[] = [{ domain: "pwn", topic: "index", reason: "pwn triage 后先读取 PWN 索引，确认题型路由。" }]
  if (/%(?:\d+\$)?[pxsdn]/i.test(haystack) || /\b(?:printf|fprintf|sprintf|snprintf|vprintf)\b/i.test(input.deepText)) {
    docs.push({ domain: "pwn", topic: "format-string", reason: "发现 format string token 或 printf-family 调用，需要确认 leak/write 路线。" })
  }
  if (/\b(?:malloc|calloc|realloc|free)\b/i.test(haystack) || /\b(?:add|delete|edit|show|chunk|tcache|fastbin|unsorted)\b/i.test(haystack)) {
    docs.push({ domain: "pwn", topic: "heap-fsop", reason: "发现 allocator/menu/chunk 线索，需要确认 heap/FSOP 路线。" })
  }
  if (/\b(?:seccomp|prctl|sandbox|orw|qemu|kernel|ioctl|bzImage|rootfs)\b/i.test(haystack)) {
    docs.push({ domain: "pwn", topic: "advanced", reason: "发现 seccomp/ORW/kernel/QEMU 或 syscall 线索，需要确认高级 PWN 路线。" })
  }
  if (/\b(?:gets|scanf|strcpy|strcat|read|recv|overflow|canary|libc|rop|system|bin\/sh|ret2|GOT|PLT)\b/i.test(haystack)) {
    docs.push({ domain: "pwn", topic: "stack-rop", reason: "发现栈输入、ROP、libc、GOT/PLT 或 shell 字符串线索，需要确认 stack/ROP 路线。" })
  }
  return dedupeRequiredDocs(docs)
}

function dedupeRequiredDocs(docs: RequiredDoc[]) {
  const seen = new Set<string>()
  return docs.filter((doc) => {
    const key = `${doc.domain}/${doc.topic}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function formatRequiredDocs(docs: RequiredDoc[]) {
  return docs
    .map(
      (doc) =>
        `- ctf_doc domain="${doc.domain}" topic="${doc.topic}" reason="${doc.reason.replaceAll('"', "'")}"`,
    )
    .join("\n")
}

function remoteBanner(host: string, port: number, timeoutMs: number) {
  return new Promise<string>((resolveBanner, reject) => {
    const socket = new Socket()
    const chunks: Buffer[] = []
    const timer = setTimeout(() => {
      socket.destroy()
      resolveBanner(Buffer.concat(chunks).toString("utf8"))
    }, timeoutMs)
    socket.setTimeout(timeoutMs)
    socket.on("data", (chunk) => {
      chunks.push(Buffer.from(chunk))
      if (Buffer.concat(chunks).length >= 4096) {
        clearTimeout(timer)
        socket.destroy()
        resolveBanner(Buffer.concat(chunks).toString("utf8"))
      }
    })
    socket.on("error", (error) => {
      clearTimeout(timer)
      reject(error)
    })
    socket.on("timeout", () => {
      clearTimeout(timer)
      socket.destroy()
      resolveBanner(Buffer.concat(chunks).toString("utf8"))
    })
    socket.on("close", () => {
      clearTimeout(timer)
      resolveBanner(Buffer.concat(chunks).toString("utf8"))
    })
    socket.connect(port, host)
  })
}

type FunctionBlock = {
  name: string
  lines: string[]
}

type DangerousCall = {
  functionName: string
  callee: string
  arg0?: string
  bounded: boolean
}

const DANGEROUS_CALLS = /(?:^|[<@_])(gets|scanf|__isoc99_scanf|strcpy|strcat|sprintf|vsprintf|read|recv|printf|system)(?:@|>|$)/i

function parseFunctions(disassembly: string) {
  const blocks: FunctionBlock[] = []
  let current: FunctionBlock | undefined
  for (const line of disassembly.split("\n")) {
    const header = line.match(/^\s*[0-9A-Fa-f]+\s+<([^>]+)>:\s*$/)
    if (header) {
      current = { name: header[1], lines: [] }
      blocks.push(current)
      continue
    }
    current?.lines.push(line)
  }
  return blocks
}

function normalizeCallee(raw: string) {
  return raw.replace(/^.*</, "").replace(/>.*$/, "").replace(/^.*\s/, "").replace(/@plt$/, "")
}

function extractStackArg0(lines: string[], callIndex: number) {
  const window = lines.slice(Math.max(0, callIndex - 8), callIndex)
  const regs = new Map<string, string>()
  const stackExpr = /\[(?:re?bp|rbp|ebp)([+-]0x[0-9A-Fa-f]+)\]/i

  for (const line of window) {
    const lea = line.match(/\blea\s+([er]?[abcds][xip]|r\d+d?|[er]di|[er]si|[er]ax),\s*(\[[^\]]+\])/i)
    if (lea) {
      const stack = lea[2].match(stackExpr)
      regs.set(lea[1].toLowerCase(), stack ? `rbp${stack[1]}` : lea[2])
      continue
    }
    const mov = line.match(/\bmov\s+([er]di|rdi|edi),\s*([er]?[abcds][xip]|r\d+d?|[er]ax)\b/i)
    if (mov) {
      const value = regs.get(mov[2].toLowerCase())
      if (value) regs.set(mov[1].toLowerCase(), value)
      continue
    }
    const push = line.match(/\bpush\s+([er]?[abcds][xip]|r\d+d?|[er]ax)\b/i)
    if (push) {
      const value = regs.get(push[1].toLowerCase())
      if (value) return value
    }
  }

  return regs.get("rdi") ?? regs.get("edi")
}

function collectDangerousCalls(disassembly: string) {
  const calls: DangerousCall[] = []
  for (const block of parseFunctions(disassembly)) {
    block.lines.forEach((line, index) => {
      if (!/\bcall[q]?\b/i.test(line) || !DANGEROUS_CALLS.test(line)) return
      const rawCallee = line.match(/<([^>]+)>/)?.[1] ?? line.trim()
      const callee = normalizeCallee(rawCallee)
      const arg0 = extractStackArg0(block.lines, index)
      const unbounded = /(^|_)(gets|strcpy|strcat|sprintf|vsprintf)($|@)/i.test(callee)
      calls.push({
        functionName: block.name.replace(/^sym\./, ""),
        callee,
        arg0,
        bounded: !unbounded && !/(scanf|__isoc99_scanf)$/i.test(callee),
      })
    })
  }
  return calls
}

function summarizeDeepPwn(disassembly: string) {
  const calls = collectDangerousCalls(disassembly)
  if (!calls.length) return ""
  return calls
    .slice(0, 24)
    .map((call) => {
      const risk = call.bounded ? "需检查长度/格式" : "无边界检查"
      const arg = call.arg0 ? `arg0=${call.arg0}` : "arg0=未静态识别"
      return `- ${call.functionName}(): calls ${call.callee}(${arg}); ${risk}`
    })
    .join("\n")
}
