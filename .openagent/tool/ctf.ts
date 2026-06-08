import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path"
import { existsSync } from "node:fs"
import { open, readFile, readdir, stat } from "node:fs/promises"
import { Socket } from "node:net"
import { spawn } from "node:child_process"
import tls from "node:tls"
import { tool, type ToolContext } from "@openagent-ai/plugin"

const z = tool.schema

const MAX_OUTPUT = 24_000
const MAX_FILE_READ = 2 * 1024 * 1024
const MAX_WEB_BODY = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 12_000
const MAX_TIMEOUT_MS = 30_000
const CTF_UA = "openagent-ctf/1.0"

type CommandSpec = {
  command: string[]
  label?: string
  input?: string
  timeoutMs?: number
}

type CommandResult = {
  label: string
  command: string
  exitCode: number | null
  stdout: string
  stderr: string
  timedOut: boolean
  skipped?: boolean
}

function clampTimeout(value?: number) {
  if (!value || Number.isNaN(value)) return DEFAULT_TIMEOUT_MS
  return Math.max(1_000, Math.min(value, MAX_TIMEOUT_MS))
}

function clip(text: string, limit = MAX_OUTPUT) {
  if (text.length <= limit) return text
  return `${text.slice(0, limit)}\n\n[truncated ${text.length - limit} chars]`
}

function code(text: string) {
  return "```text\n" + clip(text.trimEnd()) + "\n```"
}

function section(title: string, body: string | string[]) {
  const value = Array.isArray(body) ? body.filter(Boolean).join("\n") : body
  if (!value.trim()) return ""
  return `## ${title}\n${value.trim()}\n`
}

function normalizePath(input: string | undefined, ctx: ToolContext) {
  const raw = input?.trim() || ctx.directory
  const abs = isAbsolute(raw) ? raw : resolve(ctx.directory, raw)
  const root = resolve(ctx.worktree || ctx.directory)
  const rel = relative(root, abs)
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`Path is outside the configured worktree: ${abs}`)
  }
  return abs
}

async function listFiles(root: string, limit = 120) {
  const out: string[] = []
  async function walk(dir: string) {
    if (out.length >= limit) return
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => [])
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (out.length >= limit) return
      if (entry.name === "node_modules" || entry.name === ".git" || entry.name === ".git.backup-before-ctfagent") {
        continue
      }
      const full = join(dir, entry.name)
      const rel = relative(root, full) || "."
      out.push(entry.isDirectory() ? `${rel}/` : rel)
      if (entry.isDirectory()) await walk(full)
    }
  }
  await walk(root)
  return out
}

async function runCommand(cwd: string, spec: CommandSpec): Promise<CommandResult> {
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
      stdout: clip(Buffer.concat(stdout).toString("utf8"), MAX_OUTPUT / 2),
      stderr: clip(Buffer.concat(stderr).toString("utf8"), MAX_OUTPUT / 2),
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

function shellQuote(value: string) {
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) return value
  return "'" + value.replaceAll("'", "'\\''") + "'"
}

async function runBatch(cwd: string, commands: CommandSpec[]) {
  const results: CommandResult[] = []
  for (const item of commands) {
    results.push(await runCommand(cwd, item))
  }
  return results
}

function formatCommands(results: CommandResult[]) {
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

function safeUrl(raw: string) {
  const parsed = new URL(raw)
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL must start with http:// or https://")
  }
  parsed.hash = ""
  return parsed
}

function sameOrigin(base: URL, path: string) {
  const next = new URL(path, base)
  if (next.origin !== base.origin) throw new Error(`Path escapes base origin: ${path}`)
  return next
}

async function fetchText(url: URL, timeoutMs: number) {
  const started = Date.now()
  const encrypted = url.protocol === "https:"
  const port = Number(url.port || (encrypted ? 443 : 80))
  const host = url.hostname
  const hostHeader = url.port ? `${host}:${url.port}` : host
  const path = `${url.pathname || "/"}${url.search}`
  return await new Promise<{
    url: string
    status: number
    statusText: string
    contentType: string
    headers: Record<string, string>
    elapsedMs: number
    body: string
  }>((resolveResponse, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    let retained = 0
    let sent = false
    let settled = false
    const socket = encrypted
      ? tls.connect({ host, port, servername: host })
      : new Socket().connect({ host, port })
    const fail = (error: Error) => {
      if (settled) return
      settled = true
      reject(error)
    }
    const writeRequest = () => {
      if (sent) return
      sent = true
      socket.write(
        [
          `GET ${path} HTTP/1.1`,
          `Host: ${hostHeader}`,
          `User-Agent: ${CTF_UA}`,
          "Accept: text/html,text/plain,application/json,application/xml;q=0.8,*/*;q=0.2",
          "Connection: close",
          "",
          "",
        ].join("\r\n"),
      )
    }
    const finish = () => {
      if (settled) return
      settled = true
      const raw = Buffer.concat(chunks)
      const parsed = parseHttpResponse(raw)
      const body =
        parsed.truncated || total > MAX_WEB_BODY
          ? `${parsed.body}\n\n[response body exceeded ${MAX_WEB_BODY} bytes]`
          : parsed.body
      resolveResponse({
        url: url.toString(),
        status: parsed.status,
        statusText: parsed.statusText,
        contentType: parsed.headers["content-type"] ?? "",
        headers: parsed.headers,
        elapsedMs: Date.now() - started,
        body: clip(body, 16_000),
      })
    }
    socket.setTimeout(timeoutMs)
    socket.on("connect", () => {
      if (!encrypted) writeRequest()
    })
    socket.on("secureConnect", writeRequest)
    socket.on("data", (chunk) => {
      const buffer = Buffer.from(chunk)
      total += buffer.length
      if (retained < MAX_WEB_BODY) {
        const keep = buffer.subarray(0, MAX_WEB_BODY - retained)
        chunks.push(keep)
        retained += keep.length
      }
    })
    socket.on("error", fail)
    socket.on("timeout", () => {
      socket.destroy(new Error("Request timed out"))
    })
    socket.on("close", finish)
  })
}

function parseHttpResponse(raw: Buffer) {
  const boundary = raw.indexOf("\r\n\r\n")
  if (boundary < 0) {
    return { status: 0, statusText: "Invalid HTTP response", headers: {}, body: raw.toString("utf8"), truncated: false }
  }
  const head = raw.subarray(0, boundary).toString("utf8")
  const bodyRaw = raw.subarray(boundary + 4)
  const lines = head.split(/\r?\n/)
  const statusLine = lines.shift() ?? ""
  const match = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d+)\s*(.*)$/)
  const headers: Record<string, string> = {}
  for (const line of lines) {
    const index = line.indexOf(":")
    if (index <= 0) continue
    const key = line.slice(0, index).trim().toLowerCase()
    const value = line.slice(index + 1).trim()
    headers[key] = headers[key] ? `${headers[key]}; ${value}` : value
  }
  const chunked = headers["transfer-encoding"]?.toLowerCase().includes("chunked")
  const bodyBuffer = chunked ? decodeChunked(bodyRaw) : bodyRaw
  return {
    status: match ? Number(match[1]) : 0,
    statusText: match?.[2] ?? "",
    headers,
    body: bodyBuffer.toString("utf8"),
    truncated: raw.length >= MAX_WEB_BODY,
  }
}

function decodeChunked(input: Buffer) {
  const chunks: Buffer[] = []
  let offset = 0
  while (offset < input.length) {
    const end = input.indexOf("\r\n", offset)
    if (end < 0) break
    const sizeText = input.subarray(offset, end).toString("ascii").split(";")[0]?.trim() ?? "0"
    const size = Number.parseInt(sizeText, 16)
    if (!Number.isFinite(size) || size <= 0) break
    const start = end + 2
    chunks.push(input.subarray(start, start + size))
    offset = start + size + 2
  }
  return Buffer.concat(chunks)
}

function htmlSignals(html: string) {
  const comments = [...html.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]?.trim()).filter(Boolean).slice(0, 20)
  const scripts = [...html.matchAll(/<script\b[^>]*\bsrc=["']?([^"'>\s]+)/gi)].map((m) => m[1]).slice(0, 30)
  const forms = [...html.matchAll(/<form\b([^>]*)>/gi)].map((m) => m[1]?.trim()).slice(0, 20)
  const links = [...html.matchAll(/<a\b[^>]*\bhref=["']?([^"'>\s]+)/gi)].map((m) => m[1]).slice(0, 40)
  const inputs = [...html.matchAll(/<input\b([^>]*)>/gi)].map((m) => m[1]?.trim()).slice(0, 30)
  return { comments, scripts, forms, links, inputs }
}

function summarizeResponse(item: Awaited<ReturnType<typeof fetchText>>) {
  const headers = Object.entries(item.headers)
    .filter(([key]) =>
      [
        "server",
        "x-powered-by",
        "content-type",
        "set-cookie",
        "location",
        "x-frame-options",
        "content-security-policy",
        "access-control-allow-origin",
      ].includes(key),
    )
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n")
  return [
    `${item.status} ${item.statusText} ${item.url} (${item.elapsedMs}ms)`,
    headers ? `headers:\n${headers}` : "",
    `body-preview:\n${clip(item.body, 3_000)}`,
  ]
    .filter(Boolean)
    .join("\n")
}

async function readSample(file: string) {
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

function pickLikelyBinaries(files: string[]) {
  const skip = /\.(md|txt|json|jsonc|yaml|yml|png|jpg|jpeg|gif|webp|pcap|pcapng|zip|tar|gz|xz|7z)$/i
  return files.filter((item) => !item.endsWith("/") && !skip.test(item)).slice(0, 20)
}

async function isLikelyElf(file: string) {
  const sample = await readSample(file).catch(() => undefined)
  return Boolean(sample && sample.length >= 4 && sample[0] === 0x7f && sample[1] === 0x45 && sample[2] === 0x4c && sample[3] === 0x46)
}

async function selectPwnBinary(input: string | undefined, ctx: ToolContext) {
  const target = normalizePath(input, ctx)
  const info = await stat(target)
  if (info.isFile()) return target

  const files = await listFiles(target, 220)
  const candidates = pickLikelyBinaries(files).map((item) => join(target, item))
  for (const candidate of candidates) {
    if (await isLikelyElf(candidate)) return candidate
  }
  throw new Error(`No likely pwn binary found under ${target}. Pass the binary path explicitly.`)
}

async function requestPermission(ctx: ToolContext, permission: string, pattern: string, metadata: Record<string, unknown>) {
  await ctx.ask({
    permission,
    patterns: [pattern],
    always: [pattern],
    metadata,
  })
}

export const ctf_web = tool({
  description:
    "CTF Web challenge reconnaissance for an explicitly authorized challenge URL. Performs small, bounded HTTP checks: headers, robots/sitemap, common CTF paths, forms, comments, scripts, and selected custom paths.",
  args: {
    url: z.string().describe("Authorized CTF challenge base URL, for example http://127.0.0.1:8080/"),
    paths: z
      .array(z.string())
      .max(30)
      .optional()
      .describe("Additional same-origin paths to check. Keep this short and challenge-specific."),
    includeCommon: z
      .boolean()
      .optional()
      .describe("Include a small built-in common-path list. Defaults to true."),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const base = safeUrl(args.url)
    const timeoutMs = clampTimeout(args.timeoutMs)
    await requestPermission(ctx, "ctf_web", base.origin + "/*", {
      url: base.toString(),
      paths: args.paths,
      includeCommon: args.includeCommon ?? true,
    })
    ctx.metadata({ title: `CTF web: ${base.origin}`, metadata: { url: base.toString() } })

    const common = args.includeCommon === false ? [] : ["/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/flag", "/flag.txt", "/admin", "/login", "/source", "/backup.zip", "/www.zip"]
    const paths = Array.from(new Set([base.pathname || "/", ...common, ...(args.paths ?? [])])).slice(0, 40)
    const responses = []
    for (const item of paths) {
      const next = sameOrigin(base, item)
      responses.push(await fetchText(next, timeoutMs).catch((error) => ({ error: String(error), url: next.toString() })))
    }

    const root = responses.find((item): item is Awaited<ReturnType<typeof fetchText>> => "body" in item && item.url === sameOrigin(base, base.pathname || "/").toString())
    const signals = root?.body ? htmlSignals(root.body) : undefined
    const interesting = responses
      .map((item) => ("body" in item ? summarizeResponse(item) : `error ${item.url}\n${item.error}`))
      .join("\n\n---\n\n")

    return {
      title: `CTF web: ${base.origin}`,
      output: [
        section("Target", base.toString()),
        section("HTTP Checks", code(interesting)),
        section(
          "HTML Signals",
          signals
            ? [
                signals.comments.length ? `comments:\n${signals.comments.map((x) => `- ${x}`).join("\n")}` : "",
                signals.forms.length ? `forms:\n${signals.forms.map((x) => `- <form ${x}>`).join("\n")}` : "",
                signals.inputs.length ? `inputs:\n${signals.inputs.map((x) => `- <input ${x}>`).join("\n")}` : "",
                signals.scripts.length ? `scripts:\n${signals.scripts.map((x) => `- ${x}`).join("\n")}` : "",
                signals.links.length ? `links:\n${signals.links.map((x) => `- ${x}`).join("\n")}` : "",
              ]
            : "No root HTML signals available.",
        ),
        section(
          "Next Web Checks",
          [
            "- Check source disclosure, backup files, hidden routes, cookies, and auth flow.",
            "- Test likely parameters manually with small payloads only after confirming the challenge scope.",
            "- If forms or APIs are present, inspect request format before attempting injection or bypasses.",
          ],
        ),
      ].join("\n"),
      metadata: {
        target: base.toString(),
        checked: paths.length,
      },
    }
  },
})

export const ctf_reverse = tool({
  description:
    "CTF Reverse Engineering triage for local challenge files. Inventories files and runs bounded static analysis commands such as file, strings, readelf, objdump, and archive hints inside the worktree.",
  args: {
    path: z.string().optional().describe("Challenge file or directory relative to the session directory."),
    deep: z.boolean().optional().describe("Run a few extra static commands. Defaults to false."),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const target = normalizePath(args.path, ctx)
    await requestPermission(ctx, "ctf_reverse", target, { path: target, deep: args.deep ?? false })
    ctx.metadata({ title: `CTF reverse: ${basename(target)}`, metadata: { path: target } })

    const targetStat = await stat(target)
    const cwd = targetStat.isDirectory() ? target : dirname(target)
    const files = targetStat.isDirectory() ? await listFiles(target, 160) : [basename(target)]
    const candidates = targetStat.isDirectory() ? pickLikelyBinaries(files).map((item) => join(target, item)) : [target]
    const primary = candidates[0] ?? target

    const commands: CommandSpec[] = [
      { label: "file", command: ["file", "-b", primary], timeoutMs: args.timeoutMs },
      { label: "strings interesting", command: ["strings", "-a", "-n", "5", primary], timeoutMs: args.timeoutMs },
      { label: "readelf header", command: ["readelf", "-h", primary], timeoutMs: args.timeoutMs },
      { label: "readelf symbols", command: ["readelf", "-Ws", primary], timeoutMs: args.timeoutMs },
    ]
    if (args.deep) {
      commands.push(
        { label: "readelf sections", command: ["readelf", "-S", primary], timeoutMs: args.timeoutMs },
        { label: "objdump disasm head", command: ["objdump", "-d", primary], timeoutMs: args.timeoutMs },
      )
    }

    const sample = targetStat.isFile() ? await readSample(target).catch(() => undefined) : undefined
    const results = await runBatch(cwd, commands)
    const stringHints = results
      .find((item) => item.label === "strings interesting")
      ?.stdout.split("\n")
      .filter((line) => /flag|ctf|key|pass|secret|token|admin|xor|base64|rot|debug|license/i.test(line))
      .slice(0, 80)
      .join("\n")

    return {
      title: `CTF reverse: ${relative(ctx.worktree, primary) || primary}`,
      output: [
        section("Target", `${primary}\nworking-directory: ${cwd}`),
        section("Inventory", files.map((item) => `- ${item}`).join("\n")),
        sample ? section("Byte Sample", code(sample.subarray(0, 256).toString("hex").replace(/(.{32})/g, "$1\n"))) : "",
        section("Static Commands", formatCommands(results)),
        section("Interesting Strings", stringHints || "No obvious CTF strings matched the default hint list."),
        section(
          "Next Reverse Checks",
          [
            "- Identify input validation path and compare logic.",
            "- If stripped, locate main via entry point, xrefs to puts/printf/scanf/read, or string references.",
            "- Check for simple encodings, XOR loops, table lookups, anti-debug checks, and embedded archives.",
          ],
        ),
      ].join("\n"),
      metadata: {
        path: primary,
        files: files.length,
      },
    }
  },
})

export const ctf_pwn = tool({
  description:
    "CTF pwn triage for local ELF binaries and optional authorized remote banner checks. Collects protections, symbols/imports, strings, run behavior, and host:port banner with strict timeout.",
  args: {
    binary: z.string().optional().describe("ELF binary path relative to the session directory."),
    runInput: z.string().max(4096).optional().describe("Optional bounded stdin used for a local smoke run."),
    remoteHost: z.string().optional().describe("Authorized CTF remote host for banner check only."),
    remotePort: z.number().int().positive().max(65535).optional(),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const binary = await selectPwnBinary(args.binary, ctx)
    await requestPermission(ctx, "ctf_pwn", binary, {
      binary,
      remoteHost: args.remoteHost,
      remotePort: args.remotePort,
    })
    if ((args.remoteHost && !args.remotePort) || (!args.remoteHost && args.remotePort)) {
      throw new Error("remoteHost and remotePort must be provided together")
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

    return {
      title: `CTF pwn: ${relative(ctx.worktree, binary) || binary}`,
      output: [
        section("Target", binary),
        section("Binary Triage", formatCommands(results)),
        section("Risky Imports", risky || "No common risky imports matched the default hint list."),
        section("Interesting Strings", stringHints || "No common pwn strings matched the default hint list."),
        banner ? section("Remote Banner", code(banner)) : "",
        section(
          "Next Pwn Checks",
          [
            "- Confirm input surface and crash primitive with a cyclic pattern.",
            "- Determine protections: NX, PIE, canary, RELRO, libc linkage.",
            "- Choose ret2win, ret2libc, ROP, format string, heap, or logic path based on observed behavior.",
            "- Keep exploit development local first, then test against the authorized remote service.",
          ],
        ),
      ].join("\n"),
      metadata: {
        binary,
        remote: args.remoteHost && args.remotePort ? `${args.remoteHost}:${args.remotePort}` : undefined,
      },
    }
  },
})

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
