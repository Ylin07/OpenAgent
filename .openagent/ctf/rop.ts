import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path"
import { existsSync } from "node:fs"
import { writeFile } from "node:fs/promises"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_TIMEOUT_MS,
  clampTimeout,
  code,
  formatCommands,
  requestPermission,
  runBatch,
  runCommand,
  section,
  selectPwnBinary,
} from "./core.ts"
import { appendRun, challengeArgs, ensureCtfWorkspace, writeNote } from "./workspace.ts"

const z = tool.schema

function resolveReadableFile(input: string | undefined, cwd: string) {
  if (!input?.trim()) return undefined
  const path = isAbsolute(input) ? input : resolve(cwd, input)
  if (!existsSync(path)) throw new Error(`File not found: ${path}`)
  return path
}

function pyString(value: string) {
  return JSON.stringify(value)
}

function pwntoolsRopProgram(binary: string) {
  return [
    "from pwn import *",
    "context.log_level = 'error'",
    `path = ${pyString(binary)}`,
    "elf = ELF(path, checksec=False)",
    "rop = ROP(elf)",
    "print('path:', path)",
    "print('bits:', elf.bits)",
    "print('arch:', elf.arch)",
    "print('\\n[gadgets]')",
    "queries = [",
    "    ['ret'],",
    "    ['leave', 'ret'],",
    "    ['pop rdi', 'ret'], ['pop rsi', 'ret'], ['pop rdx', 'ret'], ['pop rcx', 'ret'], ['pop rax', 'ret'],",
    "    ['pop rbp', 'ret'], ['syscall'], ['int 0x80'],",
    "    ['pop eax', 'ret'], ['pop ebx', 'ret'], ['pop ecx', 'ret'], ['pop edx', 'ret'],",
    "]",
    "for query in queries:",
    "    try:",
    "        g = rop.find_gadget(query)",
    "        if g:",
    "            print('%-28s %s' % ('; '.join(query), hex(g.address)))",
    "    except Exception:",
    "        pass",
    "print('\\n[/bin/sh]')",
    "for addr in elf.search(b'/bin/sh\\x00'):",
    "    print(hex(addr))",
    "print('\\n[symbols]')",
    "for name in ['main', 'win', 'system', 'puts', 'printf', 'read', 'write', 'gets', '__libc_csu_init']:",
    "    if name in elf.symbols:",
    "        print('%-20s %s' % (name, hex(elf.symbols[name])))",
    "print('\\n[plt]')",
    "for name in ['system', 'puts', 'printf', 'read', 'write', 'gets']:",
    "    if name in elf.plt:",
    "        print('%-20s %s' % (name, hex(elf.plt[name])))",
    "print('\\n[got]')",
    "for name in ['puts', 'printf', 'read', 'write', 'gets', 'system', '__libc_start_main']:",
    "    if name in elf.got:",
    "        print('%-20s %s' % (name, hex(elf.got[name])))",
    "print('\\n[ret2csu-like]')",
    "for g in rop.gadgets.values():",
    "    ins = '; '.join(g.insns)",
    "    low = ins.lower()",
    "    if ('pop rbx' in low and 'pop rbp' in low and 'pop r12' in low and 'pop r13' in low and 'pop r14' in low and 'pop r15' in low) or ('call' in low and ('r12' in low or 'r15' in low) and ('mov rdx' in low or 'mov rsi' in low)):",
    "        print('%s : %s' % (hex(g.address), ins))",
  ].join("\n")
}

function filterLines(text: string, patterns: RegExp[], limit: number) {
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line && patterns.some((pattern) => pattern.test(line)))
  return Array.from(new Set(lines)).slice(0, limit).join("\n")
}

function usefulGadgets(text: string, limit: number) {
  return filterLines(
    text,
    [
      /\bpop rdi\b.*\bret\b/i,
      /\bpop rsi\b.*\bret\b/i,
      /\bpop rdx\b.*\bret\b/i,
      /\bpop rcx\b.*\bret\b/i,
      /\bpop rax\b.*\bret\b/i,
      /\bpop rbp\b.*\bret\b/i,
      /\bpop eax\b.*\bret\b/i,
      /\bpop ebx\b.*\bret\b/i,
      /\bpop ecx\b.*\bret\b/i,
      /\bpop edx\b.*\bret\b/i,
      /\bsyscall\b/i,
      /\bint 0x80\b/i,
      /\bleave\b.*\bret\b/i,
      /\bret\b$/i,
    ],
    limit,
  )
}

function ret2csuCandidates(text: string, limit: number) {
  return filterLines(
    text,
    [
      /\bpop rbx\b.*\bpop rbp\b.*\bpop r12\b.*\bpop r13\b.*\bpop r14\b.*\bpop r15\b.*\bret\b/i,
      /\bmov\b.*\brdx\b.*\bmov\b.*\brsi\b.*\bmov\b.*\b(?:edi|rdi)\b.*\bcall\b/i,
      /\bcall\b.*\[(r12|r15|rbx|rax|rdx|rcx|rdi|rsi)/i,
    ],
    limit,
  )
}

export const rop = tool({
  description:
    "CTF ROP 辅助：封装 ROPgadget/ropper/pwntools ROP，汇总可用 gadget、/bin/sh、syscall/int 0x80、ret2csu 候选和常用 PLT/GOT。",
  args: {
    binary: z.string().optional().describe("ELF binary 路径，相对 session directory；省略时自动选择 ELF"),
    libc: z.string().optional().describe("可选 libc 路径，用于搜索 /bin/sh；支持绝对路径"),
    python: z.string().optional().describe("Python 解释器，默认 python3"),
    depth: z.number().int().positive().max(30).optional().describe("ROPgadget depth，默认 10"),
    maxCandidates: z.number().int().positive().max(200).optional().describe("每类候选最多输出数量，默认 80"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const binary = await selectPwnBinary(args.binary, ctx)
    const libc = resolveReadableFile(args.libc, ctx.directory)
    const cwd = dirname(binary)
    const timeoutMs = clampTimeout(args.timeoutMs)
    const python = args.python?.trim() || "python3"
    const depth = args.depth ?? 10
    const maxCandidates = args.maxCandidates ?? 80

    await requestPermission(ctx, "ctf_rop", binary, { binary, libc, depth })
    if (libc) await requestPermission(ctx, "ctf_rop", libc, { binary, libc, depth })
    ctx.metadata({ title: `CTF ROP: ${basename(binary)}`, metadata: { binary, libc } })

    const commands = [
      { label: "file", command: ["file", "-b", binary], timeoutMs, maxOutput: 4_000 },
      {
        label: "ROPgadget useful",
        command: [
          "ROPgadget",
          "--binary",
          binary,
          "--depth",
          String(depth),
          "--only",
          "pop|ret|syscall|int|leave|mov|call|xchg",
        ],
        timeoutMs,
        maxOutput: 120_000,
      },
      { label: "ROPgadget /bin/sh", command: ["ROPgadget", "--binary", binary, "--string", "/bin/sh"], timeoutMs },
      { label: "ropper pop rdi", command: ["ropper", "--file", binary, "--nocolor", "--search", "pop rdi; ret"], timeoutMs },
      { label: "ropper syscall", command: ["ropper", "--file", binary, "--nocolor", "--search", "syscall"], timeoutMs },
      {
        label: "pwntools ROP",
        command: [python, "-c", pwntoolsRopProgram(binary)],
        timeoutMs,
        maxOutput: 60_000,
      },
    ]
    if (libc) {
      commands.push({ label: "ROPgadget libc /bin/sh", command: ["ROPgadget", "--binary", libc, "--string", "/bin/sh"], timeoutMs })
    }

    const results = await runBatch(cwd, commands)
    const gadgetText = results
      .filter((item) => /ROPgadget useful|ropper|pwntools ROP/i.test(item.label))
      .map((item) => [item.stdout, item.stderr].filter(Boolean).join("\n"))
      .join("\n")
    const binshText = results
      .filter((item) => /\/bin\/sh/i.test(item.label))
      .map((item) => [item.label, item.stdout, item.stderr].filter(Boolean).join("\n"))
      .join("\n\n")
    const useful = usefulGadgets(gadgetText, maxCandidates)
    const csu = ret2csuCandidates(gadgetText, maxCandidates)

    const ws = await ensureCtfWorkspace(ctx, args.challenge)
    const artifact = join(ws.artifacts, `rop-${basename(binary)}-${Date.now()}.txt`)
    await writeFile(
      artifact,
      results
        .map((result) => [
          `### ${result.label}`,
          `$ ${result.command}`,
          `exit=${result.exitCode ?? "?"}${result.timedOut ? " timeout=true" : ""}`,
          "stdout:",
          result.stdout,
          "stderr:",
          result.stderr,
        ].join("\n"))
        .join("\n\n"),
    )

    await appendRun(
      ctx,
      {
        type: "rop",
        binary,
        libc,
        artifact,
        usefulCount: useful ? useful.split("\n").length : 0,
        ret2csuCount: csu ? csu.split("\n").length : 0,
      },
      args.challenge,
    )
    await writeNote(ctx, {
      category: "pwn",
      title: `ROP candidates ${basename(binary)}`,
      content: `binary: ${binary}${libc ? `\nlibc: ${libc}` : ""}\nartifact: ${artifact}`,
      evidence: [
        useful ? `Useful gadgets:\n${useful}` : "",
        binshText.trim() ? `/bin/sh:\n${binshText.trim()}` : "",
        csu ? `ret2csu-like:\n${csu}` : "",
      ].filter(Boolean).join("\n\n"),
      next: "结合 offset、保护和 leak 选择 ret2text/ret2libc/ret2syscall/ret2csu 链，并用 pwntools 分阶段验证。",
      tags: ["pwn", "rop", basename(binary)],
      challenge: args.challenge,
    })

    return {
      title: `CTF ROP: ${relative(ctx.worktree, binary) || binary}`,
      output: [
        section("目标", [`binary: ${binary}`, libc ? `libc: ${libc}` : "libc: 未提供"]),
        section("可用 gadget 候选", useful || "未从 ROPgadget/ropper/pwntools 输出中筛到常用 gadget，查看 artifact 原始输出。"),
        section("/bin/sh 候选", binshText.trim() ? code(binshText.trim()) : "未发现 /bin/sh；如走 ret2libc，请传 libc 路径重跑。"),
        section("ret2csu 候选", csu || "未筛到典型 ret2csu gadget；可检查 __libc_csu_init 是否存在或改用普通 ROP。"),
        section("命令摘要", formatCommands(results.map((item) => ({ ...item, stdout: item.stdout.slice(0, 4_000) })))),
        section("Artifact", relative(ctx.worktree, artifact) || artifact),
      ].join("\n"),
      metadata: { binary, libc, artifact },
    }
  },
})
