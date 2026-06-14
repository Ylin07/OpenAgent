import { join } from "node:path"
import { writeFile } from "node:fs/promises"
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
} from "./core.ts"
import { appendRun, challengeArgs, ensureCtfWorkspace } from "./workspace.ts"

const z = tool.schema

export const run = tool({
  description:
    "统一受控命令执行工具。仅用于授权 CTF/lab 目录内的短命令、脚本、gdb batch、curl、python/pwntools 草稿等。默认限时且记录到 .ctf/runs.jsonl。",
  args: {
    argv: z.array(z.string()).optional().describe("推荐：按 argv 形式传命令，例如 ['file','./chall']"),
    command: z.string().optional().describe("备选：通过 bash -lc 执行的命令字符串"),
    cwd: z.string().optional().describe("执行目录，必须位于 worktree 内，默认 session directory"),
    input: z.string().max(8192).optional().describe("可选 stdin"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
    purpose: z.string().describe("为什么要执行这个命令"),
    saveOutput: z.boolean().optional().describe("是否把完整输出保存到 .ctf/artifacts"),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    if (!args.argv?.length && !args.command?.trim()) throw new Error("必须提供 argv 或 command")
    const cwd = normalizePath(args.cwd, ctx)
    const command = args.argv?.length ? args.argv : ["bash", "-lc", args.command!]
    await requestPermission(ctx, "ctf_run", `${cwd} :: ${command.join(" ")}`, {
      cwd,
      command,
      purpose: args.purpose,
    })
    ctx.metadata({ title: `CTF run: ${command[0]}`, metadata: { cwd, command, purpose: args.purpose } })

    const result = await runCommand(cwd, {
      command,
      input: args.input,
      timeoutMs: clampTimeout(args.timeoutMs),
      label: args.purpose,
    })
    const ws = await ensureCtfWorkspace(ctx, args.challenge)
    let outputPath: string | undefined
    if (args.saveOutput) {
      outputPath = join(ws.artifacts, `run-${Date.now()}.txt`)
      await writeFile(
        outputPath,
        [`$ ${result.command}`, `exit=${result.exitCode ?? "?"}`, "stdout:", result.stdout, "stderr:", result.stderr].join(
          "\n",
        ),
      )
    }
    await appendRun(
      ctx,
      {
        type: "run",
        purpose: args.purpose,
        cwd,
        command: result.command,
        exitCode: result.exitCode,
        timedOut: result.timedOut,
        outputPath,
      },
      args.challenge,
    )
    return {
      title: `CTF run: ${command[0]}`,
      output: [section("目的", args.purpose), section("结果", formatCommands([result])), outputPath ? `完整输出: ${outputPath}` : ""].join(
        "\n",
      ),
      metadata: { cwd, command, exitCode: result.exitCode, timedOut: result.timedOut, outputPath },
    }
  },
})
