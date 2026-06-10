import { dirname, isAbsolute, join, relative, resolve } from "node:path"
import { open, readFile, readdir, stat } from "node:fs/promises"
import { spawn } from "node:child_process"
import type { ToolContext } from "@openagent-ai/plugin"

export const MAX_OUTPUT = 24_000
export const MAX_FILE_READ = 2 * 1024 * 1024
export const DEFAULT_TIMEOUT_MS = 12_000
export const MAX_TIMEOUT_MS = 30_000

export type CommandSpec = {
  command: string[]
  label?: string
  input?: string
  timeoutMs?: number
  maxOutput?: number
}

export type CommandResult = {
  label: string
  command: string
  exitCode: number | null
  stdout: string
  stderr: string
  timedOut: boolean
}

export function clampTimeout(value?: number) {
  if (!value || Number.isNaN(value)) return DEFAULT_TIMEOUT_MS
  return Math.max(1_000, Math.min(value, MAX_TIMEOUT_MS))
}

export function clip(text: string, limit = MAX_OUTPUT) {
  if (text.length <= limit) return text
  return `${text.slice(0, limit)}\n\n[truncated ${text.length - limit} chars]`
}

export function code(text: string) {
  return "```text\n" + clip(text.trimEnd()) + "\n```"
}

export function section(title: string, body: string | string[]) {
  const value = Array.isArray(body) ? body.filter(Boolean).join("\n") : body
  if (!value.trim()) return ""
  return `## ${title}\n${value.trim()}\n`
}

export function normalizePath(input: string | undefined, ctx: ToolContext) {
  const raw = input?.trim() || ctx.directory
  const abs = isAbsolute(raw) ? raw : resolve(ctx.directory, raw)
  const root = resolve(ctx.worktree || ctx.directory)
  const rel = relative(root, abs)
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`路径超出当前 worktree: ${abs}`)
  }
  return abs
}

export function relativeToWorktree(path: string, ctx: ToolContext) {
  return relative(ctx.worktree || ctx.directory, path) || path
}

export async function listFiles(root: string, limit = 120) {
  const out: string[] = []
  async function walk(dir: string) {
    if (out.length >= limit) return
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (out.length >= limit) return
      if (["node_modules", ".git", ".git.backup-before-ctfagent", ".ctf"].includes(entry.name)) continue
      const full = join(dir, entry.name)
      const rel = relative(root, full) || "."
      out.push(entry.isDirectory() ? `${rel}/` : rel)
      if (entry.isDirectory()) await walk(full)
    }
  }
  await walk(root)
  return out
}

export async function runCommand(cwd: string, spec: CommandSpec): Promise<CommandResult> {
  const label = spec.label ?? spec.command.join(" ")
  const exe = spec.command[0]
  if (!exe) throw new Error("Empty command")
  let child: ReturnType<typeof spawn> | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  let timedOut = false
  try {
    child = spawn(exe, spec.command.slice(1), {
      cwd,
      env: { ...process.env, LC_ALL: "C", LANG: "C" },
      stdio: ["pipe", "pipe", "pipe"],
    })
    const stdout: Buffer[] = []
    const stderr: Buffer[] = []
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)))
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)))
    if (spec.input !== undefined) child.stdin.write(spec.input)
    child.stdin.end()
    timer = setTimeout(() => {
      timedOut = true
      child?.kill("SIGKILL")
    }, clampTimeout(spec.timeoutMs))
    const exitCode = await new Promise<number | null>((resolveExit, reject) => {
      child?.on("error", reject)
      child?.on("close", (code) => resolveExit(code))
    })
    return {
      label,
      command: spec.command.map(shellQuote).join(" "),
      exitCode,
      stdout: clip(Buffer.concat(stdout).toString("utf8"), spec.maxOutput ?? MAX_OUTPUT / 2),
      stderr: clip(Buffer.concat(stderr).toString("utf8"), spec.maxOutput ?? MAX_OUTPUT / 2),
      timedOut,
    }
  } catch (error) {
    return {
      label,
      command: spec.command.map(shellQuote).join(" "),
      exitCode: null,
      stdout: "",
      stderr: String(error),
      timedOut,
    }
  } finally {
    if (timer) clearTimeout(timer)
  }
}

export function shellQuote(value: string) {
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) return value
  return "'" + value.replaceAll("'", "'\\''") + "'"
}

export async function runBatch(cwd: string, commands: CommandSpec[]) {
  const results: CommandResult[] = []
  for (const item of commands) results.push(await runCommand(cwd, item))
  return results
}

export function formatCommands(results: CommandResult[]) {
  return results
    .map((result) => {
      const parts = [
        `### ${result.label}`,
        `$ ${result.command}`,
        `exit=${result.exitCode ?? "?"}${result.timedOut ? " timeout=true" : ""}`,
      ]
      if (result.stdout.trim()) parts.push("stdout:\n" + code(result.stdout))
      if (result.stderr.trim()) parts.push("stderr:\n" + code(result.stderr))
      return parts.join("\n")
    })
    .join("\n\n")
}

export async function readSample(file: string) {
  const info = await stat(file)
  if (info.size > MAX_FILE_READ) {
    const handle = await open(file, "r")
    try {
      const buffer = Buffer.alloc(MAX_FILE_READ)
      const result = await handle.read(buffer, 0, MAX_FILE_READ, 0)
      return buffer.subarray(0, result.bytesRead)
    } finally {
      await handle.close()
    }
  }
  return await readFile(file)
}

export function pickLikelyBinaries(files: string[]) {
  const skip = /\.(md|txt|json|jsonc|yaml|yml|png|jpg|jpeg|gif|webp|pcap|pcapng|zip|tar|gz|xz|7z)$/i
  return files.filter((item) => !item.endsWith("/") && !skip.test(item)).slice(0, 20)
}

export async function isLikelyElf(file: string) {
  const sample = await readSample(file).catch(() => undefined)
  return Boolean(
    sample &&
      sample.length >= 4 &&
      sample[0] === 0x7f &&
      sample[1] === 0x45 &&
      sample[2] === 0x4c &&
      sample[3] === 0x46,
  )
}

export async function selectPwnBinary(input: string | undefined, ctx: ToolContext) {
  const target = normalizePath(input, ctx)
  const info = await stat(target)
  if (info.isFile()) return target

  const files = await listFiles(target, 220)
  const candidates = pickLikelyBinaries(files).map((item) => join(target, item))
  for (const candidate of candidates) {
    if (await isLikelyElf(candidate)) return candidate
  }
  throw new Error(`未在 ${target} 下找到 ELF/pwn 候选文件，请显式传入 binary 路径。`)
}

export async function requestPermission(
  ctx: ToolContext,
  permission: string,
  pattern: string,
  metadata: Record<string, unknown>,
) {
  await ctx.ask({
    permission,
    patterns: [pattern],
    always: [pattern],
    metadata,
  })
}

export function dirnameForTarget(target: string) {
  return dirname(target)
}
