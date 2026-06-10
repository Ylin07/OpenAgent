import { Socket } from "node:net"
import tls from "node:tls"
import { tool } from "@openagent-ai/plugin"
import { MAX_TIMEOUT_MS, clampTimeout, clip, code, requestPermission, section } from "./core.ts"
import { appendRun, writeNote } from "./workspace.ts"

const z = tool.schema
const MAX_WEB_BODY = 1024 * 1024
const CTF_UA = "openagent-ctf/1.0"

function safeUrl(raw: string) {
  const parsed = new URL(raw)
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("URL 必须以 http:// 或 https:// 开头")
  }
  parsed.hash = ""
  return parsed
}

function sameOrigin(base: URL, path: string) {
  const next = new URL(path, base)
  if (next.origin !== base.origin) throw new Error(`路径逃逸出 base origin: ${path}`)
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
    headers: Record<string, string>
    elapsedMs: number
    body: string
  }>((resolveResponse, reject) => {
    const chunks: Buffer[] = []
    let total = 0
    let retained = 0
    let sent = false
    let settled = false
    const socket = encrypted ? tls.connect({ host, port, servername: host }) : new Socket().connect({ host, port })
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
      const parsed = parseHttpResponse(Buffer.concat(chunks))
      const body =
        parsed.truncated || total > MAX_WEB_BODY
          ? `${parsed.body}\n\n[response body exceeded ${MAX_WEB_BODY} bytes]`
          : parsed.body
      resolveResponse({
        url: url.toString(),
        status: parsed.status,
        statusText: parsed.statusText,
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
    socket.on("timeout", () => socket.destroy(new Error("Request timed out")))
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
  return {
    comments: [...html.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]?.trim()).filter(Boolean).slice(0, 20),
    scripts: [...html.matchAll(/<script\b[^>]*\bsrc=["']?([^"'>\s]+)/gi)].map((m) => m[1]).slice(0, 30),
    forms: [...html.matchAll(/<form\b([^>]*)>/gi)].map((m) => m[1]?.trim()).slice(0, 20),
    links: [...html.matchAll(/<a\b[^>]*\bhref=["']?([^"'>\s]+)/gi)].map((m) => m[1]).slice(0, 40),
    inputs: [...html.matchAll(/<input\b([^>]*)>/gi)].map((m) => m[1]?.trim()).slice(0, 30),
  }
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

export const web = tool({
  description:
    "CTF Web 工具：对授权 URL 做小范围 HTTP triage，提取 headers、robots/sitemap、常见 CTF 路径、HTML comments/forms/scripts/links。",
  args: {
    url: z.string().describe("授权 CTF Web 目标 base URL，例如 http://127.0.0.1:8080/"),
    paths: z.array(z.string()).max(30).optional().describe("额外同源路径，保持短小"),
    includeCommon: z.boolean().optional().describe("是否包含内置小型 common path，默认 true"),
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

    const common =
      args.includeCommon === false
        ? []
        : ["/", "/robots.txt", "/sitemap.xml", "/.git/HEAD", "/flag", "/flag.txt", "/admin", "/login", "/source", "/backup.zip", "/www.zip"]
    const paths = Array.from(new Set([base.pathname || "/", ...common, ...(args.paths ?? [])])).slice(0, 40)
    const responses = []
    for (const item of paths) {
      const next = sameOrigin(base, item)
      responses.push(await fetchText(next, timeoutMs).catch((error) => ({ error: String(error), url: next.toString() })))
    }
    const root = responses.find(
      (item): item is Awaited<ReturnType<typeof fetchText>> =>
        "body" in item && item.url === sameOrigin(base, base.pathname || "/").toString(),
    )
    const signals = root?.body ? htmlSignals(root.body) : undefined
    const checks = responses
      .map((item) => ("body" in item ? summarizeResponse(item) : `error ${item.url}\n${item.error}`))
      .join("\n\n---\n\n")

    await appendRun(ctx, { type: "web", target: base.toString(), checked: paths.length })
    await writeNote(ctx, {
      category: "web",
      title: `Web triage ${base.origin}`,
      content: `已检查 ${paths.length} 个同源路径。`,
      evidence: clip(checks, 4_000),
      next: "根据表单、脚本、隐藏路径和响应差异选择一个参数或入口做最小 payload 验证。",
      tags: ["web", base.origin],
    })

    return {
      title: `CTF web: ${base.origin}`,
      output: [
        section("目标", base.toString()),
        section("HTTP 检查", code(checks)),
        section(
          "HTML 线索",
          signals
            ? [
                signals.comments.length ? `comments:\n${signals.comments.map((x) => `- ${x}`).join("\n")}` : "",
                signals.forms.length ? `forms:\n${signals.forms.map((x) => `- <form ${x}>`).join("\n")}` : "",
                signals.inputs.length ? `inputs:\n${signals.inputs.map((x) => `- <input ${x}>`).join("\n")}` : "",
                signals.scripts.length ? `scripts:\n${signals.scripts.map((x) => `- ${x}`).join("\n")}` : "",
                signals.links.length ? `links:\n${signals.links.map((x) => `- ${x}`).join("\n")}` : "",
              ]
            : "没有可用 root HTML 线索。",
        ),
        section("下一步", [
          "- 检查 source disclosure、backup、hidden route、cookie、auth flow。",
          "- 对最可疑参数做小 payload 差异验证。",
          "- 如存在 JS/API，继续映射 endpoint 和请求格式。",
        ]),
      ].join("\n"),
      metadata: { target: base.toString(), checked: paths.length },
    }
  },
})
