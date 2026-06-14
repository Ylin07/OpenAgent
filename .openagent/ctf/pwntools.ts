import { basename, dirname, join, relative } from "node:path"
import { chmod, writeFile } from "node:fs/promises"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_TIMEOUT_MS,
  clampTimeout,
  code,
  formatCommands,
  normalizePath,
  requestPermission,
  runCommand,
  section,
  selectPwnBinary,
} from "./core.ts"
import { appendRun, challengeArgs, ensureCtfWorkspace, writeNote } from "./workspace.ts"

const z = tool.schema

function pyString(value: string) {
  return JSON.stringify(value)
}

function template(input: { binary?: string; remoteHost?: string; remotePort?: number }) {
  const binary = input.binary ?? "./chall"
  const host = input.remoteHost ?? "127.0.0.1"
  const port = input.remotePort ?? 31337
  return [
    "#!/usr/bin/env python3",
    "from pwn import *",
    "",
    `BINARY = ${pyString(binary)}`,
    `HOST = ${pyString(host)}`,
    `PORT = ${port}`,
    "",
    "context.binary = elf = ELF(BINARY, checksec=False)",
    "context.log_level = args.LOG_LEVEL or 'info'",
    "",
    "GDBSCRIPT = '''",
    "set pagination off",
    "break *main",
    "continue",
    "'''",
    "",
    "def start(argv=None, *a, **kw):",
    "    argv = argv or []",
    "    if args.REMOTE:",
    "        return remote(HOST, PORT)",
    "    if args.GDB:",
    "        return gdb.debug([elf.path] + argv, gdbscript=GDBSCRIPT, *a, **kw)",
    "    return process([elf.path] + argv, *a, **kw)",
    "",
    "def leak_after(io, pattern, nbytes, skip=b'\\r\\n', timeout=None):",
    "    io.recvuntil(pattern, timeout=timeout)",
    "    if not skip:",
    "        return io.recvn(nbytes, timeout=timeout)",
    "    data = b''",
    "    while len(data) < nbytes:",
    "        chunk = io.recv(1, timeout=timeout)",
    "        if not chunk:",
    "            break",
    "        if not data and chunk in skip:",
    "            continue",
    "        data += chunk",
    "    if len(data) < nbytes:",
    "        data += io.recvn(nbytes - len(data), timeout=timeout)",
    "    return data",
    "",
    "def build_payload():",
    "    # TODO: replace with the verified primitive and offset.",
    "    return b''",
    "",
    "def main():",
    "    io = start()",
    "    payload = build_payload()",
    "    if payload:",
    "        io.sendline(payload)",
    "    io.interactive()",
    "",
    "if __name__ == '__main__':",
    "    main()",
    "",
  ].join("\n")
}

function cyclicProgram(length: number, wordSize: number, crashValue?: string) {
  return [
    "from pwn import *",
    "context.log_level = 'error'",
    `pattern = cyclic(${length}, n=${wordSize})`,
    "print(pattern)",
    crashValue
      ? [
          `value = ${pyString(crashValue)}`,
          "try:",
          "    parsed = int(value, 0)",
          "except ValueError:",
          "    parsed = value.encode()",
          `print('offset:', cyclic_find(parsed, n=${wordSize}))`,
        ].join("\n")
      : "",
  ]
    .filter(Boolean)
    .join("\n")
}

export const pwntools = tool({
  description:
    "CTF pwn pwntools 辅助工具：检查 pwntools 环境、生成 exploit.py 模板、运行授权目录内的 pwntools 脚本、生成/查询 cyclic pattern。",
  args: {
    action: z.enum(["check", "template", "run", "cyclic"]).describe("操作类型"),
    python: z.string().optional().describe("Python 解释器，默认 python3；可传 venv/conda 环境里的 python 路径"),
    binary: z.string().optional().describe("ELF binary 路径；template 时会写入模板，run/cyclic 不强制需要"),
    script: z.string().optional().describe("action=run 时要执行的 pwntools 脚本路径，必须在 worktree 内"),
    cwd: z.string().optional().describe("运行目录，默认脚本所在目录或 session directory，必须在 worktree 内"),
    argv: z.array(z.string()).optional().describe("action=run 时传给脚本的参数"),
    input: z.string().max(8192).optional().describe("action=run 时可选 stdin"),
    remoteHost: z.string().optional().describe("template 中默认远程 host"),
    remotePort: z.number().int().positive().max(65535).optional().describe("template 中默认远程 port"),
    patternLength: z.number().int().positive().max(100000).optional().describe("action=cyclic 时 pattern 长度，默认 256"),
    wordSize: z.number().int().min(1).max(16).optional().describe("action=cyclic 时 cyclic n/word size，默认 4"),
    crashValue: z.string().optional().describe("action=cyclic 时可选崩溃寄存器值，例如 0x6161616b"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const python = args.python?.trim() || "python3"
    const timeoutMs = clampTimeout(args.timeoutMs)

    if (args.action === "check") {
      await requestPermission(ctx, "ctf_pwntools", python, { action: args.action, python })
      const result = await runCommand(ctx.directory, {
        label: "pwntools environment",
        command: [
          python,
          "-c",
          [
            "import sys, pwn, pwnlib",
            "print('python:', sys.executable)",
            "print('pwntools:', getattr(pwnlib, '__version__', 'unknown'))",
            "print('context.arch:', pwn.context.arch)",
          ].join("; "),
        ],
        timeoutMs,
      })
      await appendRun(ctx, { type: "pwntools", action: "check", python, exitCode: result.exitCode }, args.challenge)
      return {
        title: "CTF pwntools: check",
        output: section("环境检查", formatCommands([result])),
        metadata: { action: args.action, python, exitCode: result.exitCode },
      }
    }

    if (args.action === "template") {
      if ((args.remoteHost && !args.remotePort) || (!args.remoteHost && args.remotePort)) {
        throw new Error("remoteHost 和 remotePort 必须同时提供")
      }
      const binary = args.binary ? await selectPwnBinary(args.binary, ctx) : undefined
      const ws = await ensureCtfWorkspace(ctx, args.challenge)
      const filename = `exploit-${binary ? basename(binary).replace(/[^A-Za-z0-9_.-]/g, "_") : Date.now()}.py`
      const path = join(ws.artifacts, filename)
      await requestPermission(ctx, "ctf_pwntools", path, { action: args.action, binary, path })
      const scriptText = template({
        binary: binary ? relative(ws.artifacts, binary) || basename(binary) : undefined,
        remoteHost: args.remoteHost,
        remotePort: args.remotePort,
      })
      await writeFile(path, scriptText)
      await chmod(path, 0o755).catch(() => undefined)
      await appendRun(ctx, { type: "pwntools", action: "template", binary, path }, args.challenge)
      await writeNote(ctx, {
        category: "pwn",
        title: `pwntools 模板 ${filename}`,
        content: `已生成 pwntools exploit 模板: ${path}`,
        next: "填入已验证的 offset、leak、ROP/libc 或交互流程后，用 ctf_pwntools action=run 运行。",
        tags: ["pwn", "pwntools"],
        challenge: args.challenge,
      })
      return {
        title: "CTF pwntools: template",
        output: [section("模板路径", relative(ctx.worktree, path) || path), section("内容预览", code(scriptText))].join("\n"),
        metadata: { action: args.action, path, binary },
      }
    }

    if (args.action === "run") {
      if (!args.script) throw new Error("action=run 必须提供 script")
      const script = normalizePath(args.script, ctx)
      const cwd = args.cwd ? normalizePath(args.cwd, ctx) : dirname(script)
      const command = [python, script, ...(args.argv ?? [])]
      await requestPermission(ctx, "ctf_pwntools", `${cwd} :: ${command.join(" ")}`, {
        action: args.action,
        python,
        script,
        cwd,
      })
      ctx.metadata({ title: `CTF pwntools: ${basename(script)}`, metadata: { script, cwd } })
      const result = await runCommand(cwd, {
        label: `run ${basename(script)}`,
        command,
        input: args.input,
        timeoutMs,
      })
      await appendRun(
        ctx,
        {
          type: "pwntools",
          action: "run",
          script,
          cwd,
          exitCode: result.exitCode,
          timedOut: result.timedOut,
        },
        args.challenge,
      )
      return {
        title: `CTF pwntools: ${basename(script)}`,
        output: section("运行结果", formatCommands([result])),
        metadata: { action: args.action, script, cwd, exitCode: result.exitCode, timedOut: result.timedOut },
      }
    }

    const length = args.patternLength ?? 256
    const wordSize = args.wordSize ?? 4
    await requestPermission(ctx, "ctf_pwntools", "cyclic", {
      action: args.action,
      length,
      wordSize,
      crashValue: args.crashValue,
    })
    const result = await runCommand(ctx.directory, {
      label: "pwntools cyclic",
      command: [python, "-c", cyclicProgram(length, wordSize, args.crashValue)],
      timeoutMs,
    })
    await appendRun(
      ctx,
      {
        type: "pwntools",
        action: "cyclic",
        length,
        wordSize,
        crashValue: args.crashValue,
        exitCode: result.exitCode,
      },
      args.challenge,
    )
    return {
      title: "CTF pwntools: cyclic",
      output: section("cyclic", formatCommands([result])),
      metadata: { action: args.action, length, wordSize, crashValue: args.crashValue, exitCode: result.exitCode },
    }
  },
})
