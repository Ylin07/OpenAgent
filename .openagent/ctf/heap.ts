import { basename, dirname, join, relative } from "node:path"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { tool } from "@openagent-ai/plugin"
import {
  MAX_TIMEOUT_MS,
  clampTimeout,
  clip,
  formatCommands,
  normalizePath,
  requestPermission,
  runCommand,
  section,
} from "./core.ts"
import { appendRun, ensureCtfWorkspace, writeNote } from "./workspace.ts"

const z = tool.schema

type HeapMap = {
  start: string
  end: string
  perms?: string
  path?: string
}

type HeapChunk = {
  addr: string
  header?: string
  size: string
  chunk_size?: string
  state: string
  bin?: string
  data?: string
  fd?: string
  bk?: string
  fd_raw?: string
  bk_raw?: string
  [key: string]: unknown
}

type HeapSnapshot = {
  schema?: string
  pid?: number
  createdAt?: string
  wordSize?: number
  chunks: HeapChunk[]
  bins?: Record<string, unknown>
  maps?: HeapMap[]
  warnings?: string[]
  [key: string]: unknown
}

type Diagnostic = {
  severity: "warning" | "info"
  code: string
  message: string
  chunk?: string
  evidence?: Record<string, unknown>
}

type DiffChange = {
  kind: "added" | "removed" | "changed"
  chunk: string
  field?: string
  before?: unknown
  after?: unknown
  warning?: string
}

const JSON_START = "__CTF_HEAP_JSON_START__"
const JSON_END = "__CTF_HEAP_JSON_END__"

export const heap = tool({
  description:
    "CTF heap/ptmalloc2 辅助：对本地授权进程做 GDB heap snapshot，保存结构化 JSON；对两个快照做 diff；对单个快照检测 slot 混淆、fake chunk、bin 指针异常、size/overlap 等常见模式。",
  args: {
    action: z.enum(["snapshot", "diff", "check"]).describe("snapshot=附加 pid 生成快照；diff=比较两个 JSON；check=诊断一个 JSON"),
    pid: z.number().int().positive().optional().describe("snapshot 目标进程 PID"),
    snap: z.string().optional().describe("check 用快照路径；diff 时可作为第一个快照"),
    snap1: z.string().optional().describe("diff 的旧快照 JSON 路径"),
    snap2: z.string().optional().describe("diff 的新快照 JSON 路径"),
    snapshots: z.array(z.string()).max(2).optional().describe("diff 也可传 [snap1, snap2]"),
    output: z.string().optional().describe("snapshot 输出 JSON 路径；默认写入 .ctf/artifacts/heap-snapshot-*.json"),
    gdb: z.string().optional().describe("gdb 可执行文件，默认 gdb"),
    maxChunks: z.number().int().positive().max(4096).optional().describe("snapshot 最多解析 chunk 数，默认 512"),
    dataBytes: z.number().int().min(0).max(256).optional().describe("每个 chunk 记录的 user data 字节数，默认 32"),
    includeAnonymous: z.boolean().optional().describe("除 [heap] 外也扫描 rw anonymous mapping，默认 false"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const timeoutMs = clampTimeout(args.timeoutMs)
    if (args.action === "snapshot") {
      if (!args.pid) throw new Error("action=snapshot 需要 pid")
      const pid = args.pid
      await requestPermission(ctx, "ctf_heap", `pid:${pid}`, {
        action: args.action,
        pid,
        gdb: args.gdb?.trim() || "gdb",
      })
      ctx.metadata({ title: `CTF heap snapshot: ${pid}`, metadata: { action: args.action, pid } })
      return await executeSnapshot(
        {
          pid,
          gdb: args.gdb?.trim() || "gdb",
          output: args.output,
          maxChunks: args.maxChunks ?? 512,
          dataBytes: args.dataBytes ?? 32,
          includeAnonymous: args.includeAnonymous ?? false,
          timeoutMs,
        },
        ctx,
      )
    }

    if (args.action === "diff") {
      const snap1 = args.snap1 ?? args.snap ?? args.snapshots?.[0]
      const snap2 = args.snap2 ?? args.snapshots?.[1]
      if (!snap1 || !snap2) throw new Error("action=diff 需要 snap1/snap2，或 snapshots=[snap1, snap2]")
      await requestPermission(ctx, "ctf_heap", snap1, { action: args.action, snap1, snap2 })
      await requestPermission(ctx, "ctf_heap", snap2, { action: args.action, snap1, snap2 })
      ctx.metadata({ title: "CTF heap diff", metadata: { action: args.action, snap1, snap2 } })
      return await executeDiff(snap1, snap2, ctx)
    }

    const snap = args.snap ?? args.snap1 ?? args.snapshots?.[0]
    if (!snap) throw new Error("action=check 需要 snap")
    await requestPermission(ctx, "ctf_heap", snap, { action: args.action, snap })
    ctx.metadata({ title: "CTF heap check", metadata: { action: args.action, snap } })
    return await executeCheck(snap, ctx)
  },
})

async function executeSnapshot(
  input: {
    pid: number
    gdb: string
    output?: string
    maxChunks: number
    dataBytes: number
    includeAnonymous: boolean
    timeoutMs: number
  },
  ctx: Parameters<typeof heap.execute>[1],
) {
  const ws = await ensureCtfWorkspace(ctx)
  const timestamp = safeTimestamp()
  const scriptPath = join(ws.artifacts, `heap-snapshot-${input.pid}-${timestamp}.gdb.py`)
  const outputPath = input.output
    ? normalizePath(input.output, ctx)
    : join(ws.artifacts, `heap-snapshot-${input.pid}-${timestamp}.json`)
  await mkdir(dirname(outputPath), { recursive: true })
  await writeFile(
    scriptPath,
    buildGdbHeapScript({
      pid: input.pid,
      maxChunks: input.maxChunks,
      dataBytes: input.dataBytes,
      includeAnonymous: input.includeAnonymous,
    }),
  )

  const result = await runCommand(ctx.directory, {
    label: "gdb heap snapshot",
    command: [input.gdb, "-q", "-nx", "-batch", "-p", String(input.pid), "-x", scriptPath],
    timeoutMs: input.timeoutMs,
    maxOutput: 8_000_000,
  })
  const parsed = parseMarkedJson(result.stdout)
  if (!parsed) {
    await appendRun(ctx, {
      type: "heap-snapshot",
      pid: input.pid,
      ok: false,
      exitCode: result.exitCode,
      timedOut: result.timedOut,
    })
    return {
      title: `CTF heap snapshot failed: ${input.pid}`,
      output: [
        section("状态", "未从 gdb 输出中解析到 heap JSON。常见原因：ptrace 权限、PID 已退出、gdb 不可用，或 libc/进程状态无法读取。"),
        section("命令", formatCommands([result])),
        section("GDB script", relative(ctx.worktree, scriptPath) || scriptPath),
      ].join("\n"),
      metadata: { pid: input.pid, script: scriptPath, exitCode: result.exitCode, timedOut: result.timedOut },
    }
  }

  const snapshot = parsed as HeapSnapshot
  const pretty = JSON.stringify(snapshot, null, 2)
  await writeFile(outputPath, pretty + "\n")
  const diagnostics = diagnoseSnapshot(snapshot)
  await appendRun(ctx, {
    type: "heap-snapshot",
    pid: input.pid,
    artifact: outputPath,
    chunks: snapshot.chunks.length,
    warnings: diagnostics.filter((item) => item.severity === "warning").length + (snapshot.warnings?.length ?? 0),
  })
  await writeNote(ctx, {
    category: "pwn",
    title: `Heap snapshot pid ${input.pid}`,
    content: `pid: ${input.pid}\nartifact: ${outputPath}\nchunks: ${snapshot.chunks.length}`,
    evidence: snapshot.warnings?.length ? snapshot.warnings.map((item) => `- ${item}`).join("\n") : "",
    next: "在关键 malloc/free 前后分别跑 ctf_heap action=snapshot，再用 action=diff/action=check 定位 heap 元数据变化。",
    tags: ["pwn", "heap", `pid:${input.pid}`],
  })

  return {
    title: `CTF heap snapshot: ${input.pid}`,
    output: [
      section("Artifact", relative(ctx.worktree, outputPath) || outputPath),
      section("概览", [
        `chunks: ${snapshot.chunks.length}`,
        `tcache bins: ${arrayLength(snapshot.bins?.tcache)}`,
        `fastbins: ${arrayLength(snapshot.bins?.fastbin)}`,
        `unsorted entries: ${arrayLength(snapshot.bins?.unsorted)}`,
        snapshot.warnings?.length ? `snapshot warnings: ${snapshot.warnings.length}` : "",
      ]),
      snapshot.warnings?.length ? section("Snapshot warnings", snapshot.warnings.map((item) => `- ${item}`).join("\n")) : "",
      diagnostics.length ? section("Check preview", formatDiagnostics(diagnostics.slice(0, 12))) : "",
      section("Snapshot JSON", jsonBlock(pretty)),
    ].join("\n"),
    metadata: {
      pid: input.pid,
      artifact: outputPath,
      script: scriptPath,
      chunks: snapshot.chunks.length,
      warnings: diagnostics.length + (snapshot.warnings?.length ?? 0),
    },
  }
}

async function executeDiff(snap1: string, snap2: string, ctx: Parameters<typeof heap.execute>[1]) {
  const path1 = normalizePath(snap1, ctx)
  const path2 = normalizePath(snap2, ctx)
  const oldSnap = await readSnapshot(path1)
  const newSnap = await readSnapshot(path2)
  const changes = diffSnapshots(oldSnap, newSnap)
  const warnings = changes.filter((item) => item.warning)
  await appendRun(ctx, {
    type: "heap-diff",
    snap1: path1,
    snap2: path2,
    changes: changes.length,
    warnings: warnings.length,
  })
  await writeNote(ctx, {
    category: "pwn",
    title: `Heap diff ${basename(path1)} -> ${basename(path2)}`,
    content: `snap1: ${path1}\nsnap2: ${path2}\nchanges: ${changes.length}`,
    evidence: formatDiff(changes.slice(0, 30)),
    next: warnings.length
      ? "优先复核带 warning 的 size/bin/fd 变化；必要时回到触发点前后缩小 snapshot 间隔。"
      : "结合 malloc/free 调用点确认这些 chunk 状态变化是否符合预期。",
    tags: ["pwn", "heap", "diff"],
  })
  return {
    title: "CTF heap diff",
    output: [
      section("输入", [`snap1: ${relative(ctx.worktree, path1) || path1}`, `snap2: ${relative(ctx.worktree, path2) || path2}`]),
      section("变化", changes.length ? formatDiff(changes) : "未发现 chunk 级状态/元数据变化。"),
      section("Diff JSON", jsonBlock(JSON.stringify({ changes }, null, 2))),
    ].join("\n"),
    metadata: { snap1: path1, snap2: path2, changes: changes.length, warnings: warnings.length },
  }
}

async function executeCheck(snap: string, ctx: Parameters<typeof heap.execute>[1]) {
  const path = normalizePath(snap, ctx)
  const snapshot = await readSnapshot(path)
  const diagnostics = diagnoseSnapshot(snapshot)
  await appendRun(ctx, {
    type: "heap-check",
    snap: path,
    diagnostics: diagnostics.length,
    warnings: diagnostics.filter((item) => item.severity === "warning").length,
  })
  await writeNote(ctx, {
    category: "pwn",
    title: `Heap check ${basename(path)}`,
    content: `snapshot: ${path}\ndiagnostics: ${diagnostics.length}`,
    evidence: diagnostics.length ? formatDiagnostics(diagnostics) : "未命中默认 heap 异常模式。",
    next: diagnostics.length
      ? "先验证 warning 指向的 chunk/bin 是否来自预期漏洞 primitive，再决定 tcache poisoning、fastbin dup、unlink 或 leak 路线。"
      : "继续在关键操作前后采集快照，或扩大 maxChunks/includeAnonymous 后重跑 snapshot。",
    tags: ["pwn", "heap", "check"],
  })
  return {
    title: "CTF heap check",
    output: [
      section("输入", relative(ctx.worktree, path) || path),
      section("诊断", diagnostics.length ? formatDiagnostics(diagnostics) : "未命中默认 heap 异常模式。"),
      section("Diagnostics JSON", jsonBlock(JSON.stringify({ diagnostics }, null, 2))),
    ].join("\n"),
    metadata: {
      snap: path,
      diagnostics: diagnostics.length,
      warnings: diagnostics.filter((item) => item.severity === "warning").length,
    },
  }
}

async function readSnapshot(path: string): Promise<HeapSnapshot> {
  const raw = await readFile(path, "utf8")
  const json = extractJson(raw)
  const parsed = JSON.parse(json) as HeapSnapshot
  if (!Array.isArray(parsed.chunks)) throw new Error(`Invalid heap snapshot: ${path} 缺少 chunks[]`)
  return parsed
}

function extractJson(raw: string) {
  const trimmed = raw.trim()
  if (trimmed.startsWith("{")) return trimmed
  const marked = parseMarkedJson(trimmed)
  if (marked) return JSON.stringify(marked)
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i)
  if (fenced) return fenced[1].trim()
  throw new Error("无法从输入中提取 JSON")
}

function parseMarkedJson(text: string) {
  const start = text.indexOf(JSON_START)
  const end = text.indexOf(JSON_END)
  if (start < 0 || end < 0 || end <= start) return undefined
  const json = text.slice(start + JSON_START.length, end).trim()
  return JSON.parse(json) as unknown
}

function diffSnapshots(oldSnap: HeapSnapshot, newSnap: HeapSnapshot) {
  const changes: DiffChange[] = []
  const oldChunks = new Map(oldSnap.chunks.map((chunk) => [chunkKey(chunk), chunk] as const))
  const newChunks = new Map(newSnap.chunks.map((chunk) => [chunkKey(chunk), chunk] as const))
  const keys = new Set([...oldChunks.keys(), ...newChunks.keys()])

  for (const key of Array.from(keys).sort(compareHexish)) {
    const before = oldChunks.get(key)
    const after = newChunks.get(key)
    const name = before ? chunkName(before, oldSnap) : after ? chunkName(after, newSnap) : key
    if (!before && after) {
      changes.push({ kind: "added", chunk: name, after: summarizeChunk(after) })
      continue
    }
    if (before && !after) {
      changes.push({ kind: "removed", chunk: name, before: summarizeChunk(before) })
      continue
    }
    if (!before || !after) continue
    for (const field of ["state", "bin", "size", "chunk_size", "fd", "bk", "fd_raw", "bk_raw"] as const) {
      const oldValue = before[field]
      const newValue = after[field]
      if (oldValue === newValue) continue
      changes.push({
        kind: "changed",
        chunk: name,
        field,
        before: oldValue,
        after: newValue,
        warning: field === "size" || field === "chunk_size" ? "size 被修改" : undefined,
      })
    }
  }
  return changes
}

function diagnoseSnapshot(snapshot: HeapSnapshot) {
  const diagnostics: Diagnostic[] = []
  const chunks = snapshot.chunks
  const byAddr = groupBy(chunks, (chunk) => chunk.addr)
  const byHeader = groupBy(chunks.filter((chunk) => chunk.header), (chunk) => chunk.header ?? "")
  const entryRefs = flattenBinEntries(snapshot)
  const chunkUsers = new Set(chunks.map((chunk) => normalizeHex(chunk.addr)).filter(Boolean) as string[])
  const chunkHeaders = new Set(chunks.map((chunk) => normalizeHex(chunk.header)).filter(Boolean) as string[])

  for (const [addr, same] of byAddr) {
    if (same.length <= 1) continue
    diagnostics.push({
      severity: "warning",
      code: "duplicate_chunk_addr",
      message: `${same.map((chunk) => chunkName(chunk, snapshot)).join(" 和 ")} 指向同一地址 ${addr} -> 可能 slot 混淆`,
      chunk: addr,
      evidence: { count: same.length },
    })
  }
  for (const [header, same] of byHeader) {
    if (same.length <= 1) continue
    diagnostics.push({
      severity: "warning",
      code: "duplicate_chunk_header",
      message: `${same.map((chunk) => chunkName(chunk, snapshot)).join(" 和 ")} 共享 chunk header ${header}`,
      chunk: header,
      evidence: { count: same.length },
    })
  }

  for (const [entry, refs] of groupBy(entryRefs, (item) => item.entry)) {
    if (refs.length <= 1) continue
    diagnostics.push({
      severity: "warning",
      code: "duplicate_bin_entry",
      message: `${entry} 在多个 bin 链中重复出现 -> 可能 double free / bin dup`,
      chunk: entry,
      evidence: { refs: refs.map((item) => item.bin) },
    })
  }

  for (const item of entryRefs) {
    const normalized = normalizeHex(item.entry)
    if (!normalized) continue
    const known = chunkUsers.has(normalized) || chunkHeaders.has(normalized)
    if (known) continue
    diagnostics.push({
      severity: isMapped(snapshot, item.entry) ? "info" : "warning",
      code: isMapped(snapshot, item.entry) ? "bin_entry_not_in_chunks" : "bin_entry_unmapped",
      message: isMapped(snapshot, item.entry)
        ? `${item.bin} entry ${item.entry} 不在解析到的 chunk 列表中 -> 可能 fake chunk 或扫描范围不足`
        : `${item.bin} entry ${item.entry} 指向未映射地址 -> 可能 crash`,
      chunk: item.entry,
      evidence: item,
    })
  }

  for (const chunk of chunks) {
    const name = chunkName(chunk, snapshot)
    const state = String(chunk.state ?? "")
    if (state === "allocated" && entryRefs.some((item) => sameHex(item.entry, chunk.addr) || sameHex(item.entry, chunk.header))) {
      diagnostics.push({
        severity: "warning",
        code: "allocated_in_bin",
        message: `${name} state=allocated 但仍出现在 bin 链中 -> 可能 UAF / 元数据不一致`,
        chunk: chunk.addr,
      })
    }
    for (const field of ["fd", "bk"] as const) {
      const value = chunk[field]
      if (!isPointerLike(value) || isNullPtr(value)) continue
      if (!isMapped(snapshot, value)) {
        diagnostics.push({
          severity: "warning",
          code: `${field}_unmapped`,
          message: `${name}.${field}=${value} 指向未映射地址 -> 可能 fake chunk / poisoned pointer，继续解引用可能 crash`,
          chunk: chunk.addr,
          evidence: { [field]: value, bin: chunk.bin, state: chunk.state },
        })
      }
    }
    const chunkSize = chunkSizeOf(chunk, snapshot.wordSize)
    if (chunkSize !== undefined && chunkSize < BigInt((snapshot.wordSize ?? 8) * 2)) {
      diagnostics.push({
        severity: "warning",
        code: "chunk_size_too_small",
        message: `${name}.size=${chunk.size} 小于最小 chunk header 尺寸`,
        chunk: chunk.addr,
      })
    }
  }

  const sorted = chunks
    .map((chunk) => ({ chunk, header: parseHex(chunk.header ?? chunk.addr), size: chunkSizeOf(chunk, snapshot.wordSize) }))
    .filter((item): item is { chunk: HeapChunk; header: bigint; size: bigint } => item.header !== undefined && item.size !== undefined)
    .sort((a, b) => (a.header < b.header ? -1 : a.header > b.header ? 1 : 0))
  for (let index = 1; index < sorted.length; index++) {
    const previous = sorted[index - 1]
    const current = sorted[index]
    const previousEnd = previous.header + previous.size
    if (current.header < previousEnd) {
      diagnostics.push({
        severity: "warning",
        code: "chunk_overlap",
        message: `${chunkName(previous.chunk, snapshot)} 与 ${chunkName(current.chunk, snapshot)} chunk range 重叠`,
        chunk: current.chunk.addr,
        evidence: { previousEnd: hex(previousEnd), currentHeader: hex(current.header) },
      })
    }
  }

  return diagnostics
}

function formatDiff(changes: DiffChange[]) {
  if (!changes.length) return ""
  return changes
    .map((change) => {
      if (change.kind === "added") return `- ${change.chunk}: added ${JSON.stringify(change.after)}`
      if (change.kind === "removed") return `- ${change.chunk}: removed ${JSON.stringify(change.before)}`
      const warning = change.warning ? `  ⚠️  ${change.warning}` : ""
      return `- ${change.chunk}.${change.field}: ${stringValue(change.before)} -> ${stringValue(change.after)}${warning}`
    })
    .join("\n")
}

function formatDiagnostics(diagnostics: Diagnostic[]) {
  return diagnostics
    .map((item) => {
      const prefix = item.severity === "warning" ? "⚠️" : "ℹ️"
      return `${prefix} [${item.code}] ${item.message}`
    })
    .join("\n")
}

function jsonBlock(text: string) {
  return "```json\n" + clip(text, 40_000) + "\n```"
}

function chunkKey(chunk: HeapChunk) {
  return normalizeHex(chunk.addr) ?? normalizeHex(chunk.header) ?? chunk.addr
}

function chunkName(chunk: HeapChunk, snapshot: HeapSnapshot) {
  const index = snapshot.chunks.indexOf(chunk)
  return index >= 0 ? `chunk${index + 1}@${chunk.addr}` : `chunk@${chunk.addr}`
}

function summarizeChunk(chunk: HeapChunk) {
  return {
    addr: chunk.addr,
    header: chunk.header,
    size: chunk.size,
    state: chunk.state,
    bin: chunk.bin,
    fd: chunk.fd,
    bk: chunk.bk,
  }
}

function flattenBinEntries(snapshot: HeapSnapshot) {
  const out: Array<{ bin: string; entry: string; index?: number }> = []
  const bins = snapshot.bins ?? {}
  for (const [binName, value] of Object.entries(bins)) collectBinEntries(binName, value, out)
  return out
}

function collectBinEntries(bin: string, value: unknown, out: Array<{ bin: string; entry: string; index?: number }>) {
  if (typeof value === "string") {
    if (isPointerLike(value) && !isNullPtr(value)) out.push({ bin, entry: value })
    return
  }
  if (!value || typeof value !== "object") return
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      if (typeof item === "string") {
        if (isPointerLike(item) && !isNullPtr(item)) out.push({ bin, entry: item, index })
      } else collectBinEntries(`${bin}[${index}]`, item, out)
    })
    return
  }
  const record = value as Record<string, unknown>
  const entries = record.entries
  if (Array.isArray(entries)) {
    entries.forEach((entry, index) => {
      if (typeof entry === "string" && !isNullPtr(entry)) out.push({ bin, entry, index })
    })
  }
  for (const [key, nested] of Object.entries(record)) {
    if (key === "entries") continue
    if (Array.isArray(nested) || (nested && typeof nested === "object")) collectBinEntries(`${bin}.${key}`, nested, out)
  }
}

function groupBy<T>(items: T[], key: (item: T) => string) {
  const map = new Map<string, T[]>()
  for (const item of items) {
    const value = key(item)
    if (!value) continue
    const bucket = map.get(value) ?? []
    bucket.push(item)
    map.set(value, bucket)
  }
  return map
}

function chunkSizeOf(chunk: HeapChunk, wordSize = 8) {
  const raw = parseHex(chunk.chunk_size ?? chunk.size)
  if (raw === undefined) return undefined
  const align = BigInt(wordSize * 2)
  return raw & ~(align - 1n)
}

function isMapped(snapshot: HeapSnapshot, value: unknown) {
  const ptr = parseHex(value)
  if (ptr === undefined) return false
  const maps = snapshot.maps ?? []
  return maps.some((map) => {
    const start = parseHex(map.start)
    const end = parseHex(map.end)
    return start !== undefined && end !== undefined && start <= ptr && ptr < end
  })
}

function isPointerLike(value: unknown): value is string {
  return typeof value === "string" && /^0x[0-9a-f]+$/i.test(value)
}

function isNullPtr(value: unknown) {
  const ptr = parseHex(value)
  return ptr === 0n
}

function sameHex(a: unknown, b: unknown) {
  const left = parseHex(a)
  const right = parseHex(b)
  return left !== undefined && right !== undefined && left === right
}

function normalizeHex(value: unknown) {
  const ptr = parseHex(value)
  return ptr === undefined ? undefined : hex(ptr)
}

function parseHex(value: unknown) {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) return undefined
  return BigInt(value)
}

function hex(value: bigint) {
  return `0x${value.toString(16)}`
}

function compareHexish(a: string, b: string) {
  const left = parseHex(a)
  const right = parseHex(b)
  if (left !== undefined && right !== undefined) return left < right ? -1 : left > right ? 1 : 0
  return a.localeCompare(b)
}

function stringValue(value: unknown) {
  if (value === undefined) return "undefined"
  if (typeof value === "string") return value
  return JSON.stringify(value)
}

function arrayLength(value: unknown) {
  return Array.isArray(value) ? value.length : 0
}

function safeTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-")
}

function buildGdbHeapScript(input: {
  pid: number
  maxChunks: number
  dataBytes: number
  includeAnonymous: boolean
}) {
  return String.raw`
import gdb
import json
import os
import time
import traceback

PID = ${input.pid}
MAX_CHUNKS = ${input.maxChunks}
DATA_BYTES = ${input.dataBytes}
INCLUDE_ANONYMOUS = ${input.includeAnonymous ? "True" : "False"}
JSON_START = "${JSON_START}"
JSON_END = "${JSON_END}"

warnings = []
inf = gdb.selected_inferior()

def hx(value):
    if value is None:
        return None
    return "0x%x" % int(value)

def to_int(value):
    try:
        return int(value)
    except Exception:
        try:
            return int(value.cast(gdb.lookup_type("unsigned long")))
        except Exception:
            return 0

def read_mem(addr, size):
    return bytes(inf.read_memory(int(addr), int(size)))

def read_uint(addr, ptr_size):
    try:
        return int.from_bytes(read_mem(addr, ptr_size), "little")
    except Exception:
        return None

def mapped(maps, addr):
    return any(m["start_i"] <= addr < m["end_i"] for m in maps)

def mapping_for(maps, addr):
    for item in maps:
        if item["start_i"] <= addr < item["end_i"]:
            return item
    return None

def parse_maps():
    out = []
    with open("/proc/%d/maps" % PID, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 5:
                continue
            start_s, end_s = parts[0].split("-", 1)
            path = parts[5] if len(parts) >= 6 else ""
            item = {
                "start_i": int(start_s, 16),
                "end_i": int(end_s, 16),
                "start": "0x" + start_s,
                "end": "0x" + end_s,
                "perms": parts[1],
                "path": path,
            }
            out.append(item)
    return out

def valid_chunk_header(addr, limit, ptr_size, mask, align):
    size_raw = read_uint(addr + ptr_size, ptr_size)
    if size_raw is None:
        return False
    size = size_raw & mask
    if size < ptr_size * 2:
        return False
    if size % align != 0:
        return False
    if addr + size > limit:
        return False
    return True

def find_first_chunk(mapping, ptr_size, mask, align):
    end = mapping["end_i"]
    scan_end = min(mapping["start_i"] + 0x1000, end)
    addr = mapping["start_i"]
    while addr + ptr_size * 2 <= scan_end:
        if valid_chunk_header(addr, end, ptr_size, mask, align):
            return addr
        addr += align
    return None

def decode_safelink(pos, value, maps):
    if value in (None, 0):
        return value
    decoded = int(value) ^ (int(pos) >> 12)
    if mapped(maps, decoded):
        return decoded
    if mapped(maps, int(value)):
        return int(value)
    return decoded

def collect_tcache(ptr_size, align, maps):
    result = []
    try:
        tcache_ptr = gdb.parse_and_eval("tcache")
        if to_int(tcache_ptr) == 0:
            return result
        tcache = tcache_ptr.dereference()
        counts = tcache["counts"]
        entries = tcache["entries"]
        for idx in range(64):
            try:
                count = int(counts[idx])
                head = to_int(entries[idx])
            except Exception:
                continue
            if count <= 0 and head == 0:
                continue
            chain = []
            seen = set()
            current = head
            limit = max(count, 8) + 8
            while current and current not in seen and len(chain) < limit:
                seen.add(current)
                chain.append(hx(current))
                raw_next = read_uint(current, ptr_size)
                if raw_next in (None, 0):
                    break
                current = decode_safelink(current, raw_next, maps)
                if not mapped(maps, current):
                    chain.append(hx(current))
                    break
            result.append({
                "index": idx,
                "size": hx(idx * align + ptr_size * 4),
                "count": count,
                "entries": chain,
            })
    except Exception as exc:
        warnings.append("tcache unavailable: %s" % exc)
    return result

def collect_arena(ptr_size, align, maps):
    meta = {"fastbin": [], "unsorted": [], "top": None}
    try:
        arena = gdb.parse_and_eval("main_arena")
    except Exception as exc:
        warnings.append("main_arena unavailable: %s" % exc)
        return meta

    try:
        meta["top"] = hx(to_int(arena["top"]))
    except Exception as exc:
        warnings.append("main_arena.top unavailable: %s" % exc)

    try:
        fastbins = arena["fastbinsY"]
        for idx in range(10):
            head = to_int(fastbins[idx])
            chain = []
            seen = set()
            current = head
            while current and current not in seen and len(chain) < 64:
                seen.add(current)
                chain.append(hx(current))
                user = current + ptr_size * 2
                raw_next = read_uint(user, ptr_size)
                if raw_next in (None, 0):
                    break
                current = decode_safelink(user, raw_next, maps)
                if not mapped(maps, current):
                    chain.append(hx(current))
                    break
            if head or chain:
                meta["fastbin"].append({
                    "index": idx,
                    "size": hx((idx + 2) * align),
                    "entries": chain,
                })
    except Exception as exc:
        warnings.append("fastbins unavailable: %s" % exc)

    try:
        bins = arena["bins"]
        sentinel = to_int(bins.address) - ptr_size * 2
        head = to_int(bins[0])
        chain = []
        seen = set()
        current = head
        while current and current != sentinel and current not in seen and len(chain) < 128:
            seen.add(current)
            chain.append(hx(current))
            fd = read_uint(current + ptr_size * 2, ptr_size)
            if fd in (None, 0):
                break
            current = fd
            if current != sentinel and not mapped(maps, current):
                chain.append(hx(current))
                break
        if chain:
            meta["unsorted"].append({
                "index": 1,
                "sentinel": hx(sentinel),
                "entries": chain,
            })
    except Exception as exc:
        warnings.append("unsorted bin unavailable: %s" % exc)

    return meta

def bin_indexes(bins, ptr_size):
    by_header = {}
    by_user = {}
    for item in bins.get("tcache", []):
        for entry in item.get("entries", []):
            by_user[entry] = "tcache"
    for item in bins.get("fastbin", []):
        for entry in item.get("entries", []):
            by_header[entry] = "fastbin"
            try:
                by_user[hx(int(entry, 16) + ptr_size * 2)] = "fastbin"
            except Exception:
                pass
    for item in bins.get("unsorted", []):
        for entry in item.get("entries", []):
            by_header[entry] = "unsorted"
            try:
                by_user[hx(int(entry, 16) + ptr_size * 2)] = "unsorted"
            except Exception:
                pass
    return by_header, by_user

def classify_chunk(header, user, top, by_header, by_user, next_size_raw):
    header_s = hx(header)
    user_s = hx(user)
    if header_s == top:
        return "top", "top"
    if user_s in by_user:
        return "freed", by_user[user_s]
    if header_s in by_header:
        return "freed", by_header[header_s]
    if next_size_raw is not None and (next_size_raw & 1) == 0:
        return "freed", None
    return "allocated", None

def parse_chunks(heap_maps, ptr_size, align, mask, bins, maps):
    chunks = []
    top = bins.get("top")
    by_header, by_user = bin_indexes(bins, ptr_size)
    for mapping in heap_maps:
        current = find_first_chunk(mapping, ptr_size, mask, align)
        if current is None:
            warnings.append("no valid chunk header found in mapping %s-%s %s" % (mapping["start"], mapping["end"], mapping.get("path", "")))
            continue
        while current and current + ptr_size * 2 <= mapping["end_i"] and len(chunks) < MAX_CHUNKS:
            if not valid_chunk_header(current, mapping["end_i"], ptr_size, mask, align):
                warnings.append("invalid chunk header at %s; stop mapping walk" % hx(current))
                break
            prev_size = read_uint(current, ptr_size)
            size_raw = read_uint(current + ptr_size, ptr_size)
            size = size_raw & mask
            user = current + ptr_size * 2
            next_header = current + size
            next_size_raw = None
            if next_header + ptr_size * 2 <= mapping["end_i"]:
                next_size_raw = read_uint(next_header + ptr_size, ptr_size)
            state, bin_name = classify_chunk(current, user, top, by_header, by_user, next_size_raw)
            user_size = max(0, size - ptr_size * 2)
            data = ""
            if DATA_BYTES > 0 and user_size > 0:
                try:
                    data = read_mem(user, min(DATA_BYTES, user_size)).hex()
                except Exception:
                    data = ""
            fd_raw = read_uint(user, ptr_size) if user_size >= ptr_size else None
            bk_raw = read_uint(user + ptr_size, ptr_size) if user_size >= ptr_size * 2 else None
            fd = fd_raw
            bk = bk_raw
            if state == "freed" and bin_name in ("tcache", "fastbin") and fd_raw not in (None, 0):
                pos = user if bin_name == "tcache" else user
                fd = decode_safelink(pos, fd_raw, maps)
            chunk = {
                "addr": hx(user),
                "header": hx(current),
                "size": hx(size_raw),
                "chunk_size": hx(size),
                "prev_size": hx(prev_size),
                "state": state,
                "data": data,
            }
            if bin_name:
                chunk["bin"] = bin_name
            if state == "freed":
                if fd is not None:
                    chunk["fd"] = hx(fd)
                    chunk["fd_raw"] = hx(fd_raw)
                if bk is not None and bin_name not in ("tcache", "fastbin"):
                    chunk["bk"] = hx(bk)
                    chunk["bk_raw"] = hx(bk_raw)
            chunks.append(chunk)
            if size <= 0:
                break
            current = next_header
    return chunks

try:
    gdb.execute("set pagination off", to_string=True)
    gdb.execute("set confirm off", to_string=True)
    arch = gdb.selected_frame().architecture().name()
    ptr_size = int(gdb.parse_and_eval("sizeof(void*)"))
    align = ptr_size * 2
    mask = ~int(align - 1)
    maps_full = parse_maps()
    heap_maps = []
    for item in maps_full:
        anonymous = item["path"] == "" and item["perms"].startswith("rw")
        if item["path"] == "[heap]" or (INCLUDE_ANONYMOUS and anonymous):
            heap_maps.append(item)
    bins = collect_arena(ptr_size, align, maps_full)
    bins["tcache"] = collect_tcache(ptr_size, align, maps_full)
    chunks = parse_chunks(heap_maps, ptr_size, align, mask, bins, maps_full)
    public_maps = [
        {k: item[k] for k in ("start", "end", "perms", "path")}
        for item in maps_full
    ]
    snapshot = {
        "schema": "ctf_heap_snapshot/v1",
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": PID,
        "arch": arch,
        "wordSize": ptr_size,
        "chunks": chunks,
        "bins": {
            "tcache": bins.get("tcache", []),
            "fastbin": bins.get("fastbin", []),
            "unsorted": bins.get("unsorted", []),
        },
        "maps": public_maps,
        "warnings": warnings,
    }
except Exception:
    snapshot = {
        "schema": "ctf_heap_snapshot/v1",
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": PID,
        "chunks": [],
        "bins": {"tcache": [], "fastbin": [], "unsorted": []},
        "maps": [],
        "warnings": warnings + [traceback.format_exc()],
    }

print(JSON_START)
print(json.dumps(snapshot, sort_keys=True))
print(JSON_END)
`
}
