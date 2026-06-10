import { basename, dirname, isAbsolute, relative, resolve } from "node:path"
import { existsSync } from "node:fs"
import { readFile, writeFile } from "node:fs/promises"
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
} from "./core.ts"
import { appendRun, ensureCtfWorkspace, writeNote } from "./workspace.ts"

const z = tool.schema

type LeakInput = {
  symbol: string
  address: string
  offset?: string
  note?: string
}

type LibcInfo = {
  path: string
  arch: string
  bits: number
  symbols: Record<string, number>
  binsh?: number
}

type LibcRipCandidate = {
  id?: string
  buildid?: string
  download_url?: string
  symbols_url?: string
  symbols?: Record<string, string>
}

type RemoteLibcLookup = {
  query: Record<string, string>
  candidates: LibcRipCandidate[]
  error?: string
}

function pyString(value: string) {
  return JSON.stringify(value)
}

function resolveReadableFile(input: string | undefined, cwd: string) {
  if (!input?.trim()) return undefined
  const path = isAbsolute(input) ? input : resolve(cwd, input)
  if (!existsSync(path)) throw new Error(`File not found: ${path}`)
  return path
}

function parseAddress(value: string | undefined) {
  if (!value?.trim()) return undefined
  const raw = value.trim()
  if (/^0x[0-9a-f]+$/i.test(raw)) return BigInt(raw)
  if (/^[0-9]+$/.test(raw)) return BigInt(raw)
  throw new Error(`Invalid address/offset: ${value}`)
}

function hex(value: bigint | undefined) {
  if (value === undefined) return undefined
  return `0x${value.toString(16)}`
}

function parseHexOffset(value: string | undefined) {
  if (!value) return undefined
  return parseAddress(value)
}

function low12(value: bigint) {
  return (value & 0xfffn).toString(16)
}

function parseSymbolExpr(input: string) {
  const raw = input.trim()
  const match = raw.match(/^([A-Za-z0-9_.$@]+)(?:([+-])((?:0x)?[0-9A-Fa-f]+))?$/)
  if (!match) return { name: raw, addend: 0n }
  const name = match[1].split("@")[0]
  const magnitude = parseAddress(match[3]) ?? 0n
  return { name, addend: match[2] === "-" ? -magnitude : magnitude }
}

function libcInfoProgram(libc: string, symbols: string[]) {
  return [
    "from pwn import *",
    "import json",
    "context.log_level = 'error'",
    `path = ${pyString(libc)}`,
    `wanted = ${JSON.stringify(symbols)}`,
    "elf = ELF(path, checksec=False)",
    "out = {'path': path, 'arch': elf.arch, 'bits': elf.bits, 'symbols': {}}",
    "for name in sorted(set(wanted + ['system', 'puts', 'printf', 'read', 'write', 'gets', 'malloc', 'free', '__libc_start_main', '__free_hook', '__malloc_hook', 'setcontext'])):",
    "    key = name.split('@')[0]",
    "    if key in elf.symbols:",
    "        out['symbols'][key] = int(elf.symbols[key])",
    "try:",
    "    out['binsh'] = int(next(elf.search(b'/bin/sh\\x00')))",
    "except StopIteration:",
    "    pass",
    "print(json.dumps(out, sort_keys=True))",
  ].join("\n")
}

async function inferLocalLibc(binary: string, timeoutMs: number) {
  const result = await runCommand(dirname(binary), {
    label: "ldd infer libc",
    command: ["ldd", binary],
    timeoutMs,
    maxOutput: 8_000,
  })
  const text = `${result.stdout}\n${result.stderr}`
  const match = text.match(/(?:=>\s*)?(\/\S*libc(?:-[0-9.]+)?\.so(?:\.\d+)*)\s*(?:\(|$)/)
  return { path: match?.[1], result }
}

function parseOneGadgetOffsets(text: string) {
  return Array.from(new Set((text.match(/0x[0-9A-Fa-f]+/g) ?? []).map((item) => BigInt(item)))).slice(0, 80)
}

function parseState(raw: string) {
  try {
    return JSON.parse(raw || "{}") as Record<string, unknown>
  } catch {
    return {}
  }
}

function formatLeaks(leaks: LeakInput[] | undefined) {
  if (!leaks?.length) return "未提供 leak。"
  return leaks
    .map((leak) => `- ${leak.symbol}${leak.offset ? `+${leak.offset}` : ""} @ ${leak.address}${leak.note ? ` (${leak.note})` : ""}`)
    .join("\n")
}

function formatBaseCandidates(candidates: Array<{ leak: LeakInput; base: bigint; aligned: boolean }>) {
  if (!candidates.length) return "没有可计算的 libc base 候选；需要 libc 符号偏移和至少一个 leak。"
  return candidates
    .map((item) => {
      const status = item.aligned ? "page_aligned" : "not_page_aligned"
      return `- ${item.leak.symbol}@${item.leak.address} -> base=${hex(item.base)} ${status}`
    })
    .join("\n")
}

function formatResolved(input: {
  base?: bigint
  info?: LibcInfo
  oneGadgets: bigint[]
}) {
  if (!input.info) return "未加载 libc，无法解析 system/binsh/one_gadget 地址。"
  const rows: string[] = []
  const symbols = ["system", "puts", "printf", "read", "write", "__libc_start_main", "__free_hook", "__malloc_hook", "setcontext"]
  for (const name of symbols) {
    const offset = input.info.symbols[name]
    if (offset === undefined) continue
    const off = BigInt(offset)
    rows.push(`- ${name}: offset=${hex(off)}${input.base !== undefined ? ` addr=${hex(input.base + off)}` : ""}`)
  }
  if (input.info.binsh !== undefined) {
    const off = BigInt(input.info.binsh)
    rows.push(`- /bin/sh: offset=${hex(off)}${input.base !== undefined ? ` addr=${hex(input.base + off)}` : ""}`)
  }
  if (input.oneGadgets.length) {
    for (const off of input.oneGadgets.slice(0, 12)) {
      rows.push(`- one_gadget: offset=${hex(off)}${input.base !== undefined ? ` addr=${hex(input.base + off)}` : ""}`)
    }
    if (input.oneGadgets.length > 12) rows.push(`- one_gadget: ... ${input.oneGadgets.length - 12} more`)
  }
  return rows.length ? rows.join("\n") : "libc 已加载，但未找到常用符号。"
}

function buildLibcRipQueries(leaks: LeakInput[]) {
  const normal: Record<string, string> = {}
  let libcStartMainRet: string | undefined

  for (const leak of leaks) {
    const leaked = parseAddress(leak.address)
    if (leaked === undefined) continue
    const parsed = parseSymbolExpr(leak.symbol)
    const explicitOffset = parseAddress(leak.offset)
    const addend = explicitOffset ?? parsed.addend
    normal[parsed.name] = low12(leaked - addend)
    if (parsed.name === "__libc_start_main" && addend !== 0n) {
      libcStartMainRet = low12(leaked)
    }
  }

  const queries: Array<Record<string, string>> = []
  if (libcStartMainRet) {
    const retAdjusted = { ...normal, __libc_start_main_ret: libcStartMainRet }
    delete retAdjusted.__libc_start_main
    queries.push(retAdjusted)
  }
  queries.push(normal)
  return queries.filter((query) => Object.keys(query).length > 0)
}

async function queryLibcRip(leaks: LeakInput[], timeoutMs: number): Promise<RemoteLibcLookup | undefined> {
  const queries = buildLibcRipQueries(leaks)
  if (!queries.length) return undefined
  let lastError: string | undefined
  for (const query of queries) {
    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      const response = await fetch("https://libc.rip/api/find", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ symbols: query }),
        signal: controller.signal,
      })
      clearTimeout(timer)
      if (!response.ok) {
        lastError = `HTTP ${response.status}`
        continue
      }
      const json = await response.json()
      const candidates = Array.isArray(json) ? (json as LibcRipCandidate[]) : []
      if (candidates.length) return { query, candidates }
      lastError = "no candidates"
    } catch (error) {
      lastError = String(error)
    }
  }
  return { query: queries[queries.length - 1], candidates: [], error: lastError }
}

function remoteBaseRows(candidate: LibcRipCandidate, leaks: LeakInput[]) {
  const rows: Array<{ symbol: string; address: string; base: bigint; aligned: boolean }> = []
  for (const leak of leaks) {
    const parsed = parseSymbolExpr(leak.symbol)
    const leaked = parseAddress(leak.address)
    if (leaked === undefined) continue
    const explicitOffset = parseAddress(leak.offset)
    const addend = explicitOffset ?? parsed.addend
    const symbolName =
      parsed.name === "__libc_start_main" && addend !== 0n && candidate.symbols?.__libc_start_main_ret
        ? "__libc_start_main_ret"
        : parsed.name
    const rawOffset = candidate.symbols?.[symbolName]
    const symbolOffset = parseHexOffset(rawOffset)
    if (symbolOffset === undefined) continue
    const base = symbolName === "__libc_start_main_ret" ? leaked - symbolOffset : leaked - symbolOffset - addend
    rows.push({ symbol: symbolName, address: leak.address, base, aligned: (base & 0xfffn) === 0n })
  }
  return rows
}

function formatRemoteLibcLookup(lookup: RemoteLibcLookup | undefined, leaks: LeakInput[]) {
  if (!lookup) return "未触发在线 libc 查询：需要至少一个 leak。"
  const query = Object.entries(lookup.query)
    .map(([name, value]) => `${name}=${value}`)
    .join(", ")
  if (lookup.error && !lookup.candidates.length) return `query: ${query}\nlibc.rip 查询失败或无结果: ${lookup.error}`
  if (!lookup.candidates.length) return `query: ${query}\nlibc.rip 未返回候选。`

  const rows = lookup.candidates.slice(0, 12).map((candidate, index) => {
    const bases = remoteBaseRows(candidate, leaks)
    const selectedBase = bases.find((item) => item.aligned)?.base ?? bases[0]?.base
    const system = selectedBase !== undefined ? parseHexOffset(candidate.symbols?.system) : undefined
    const binsh = selectedBase !== undefined ? parseHexOffset(candidate.symbols?.str_bin_sh) : undefined
    return [
      `- #${index + 1} ${candidate.id ?? "unknown-libc"}`,
      candidate.buildid ? `buildid=${candidate.buildid}` : "",
      selectedBase !== undefined ? `base=${hex(selectedBase)}` : "",
      system !== undefined && selectedBase !== undefined ? `system=${hex(selectedBase + system)}` : "",
      binsh !== undefined && selectedBase !== undefined ? `bin_sh=${hex(selectedBase + binsh)}` : "",
      candidate.download_url ? `download=${candidate.download_url}` : "",
    ].filter(Boolean).join(" ")
  })
  if (lookup.candidates.length > rows.length) rows.push(`- ... ${lookup.candidates.length - rows.length} more candidates omitted`)
  return [`query: ${query}`, ...rows].join("\n")
}

export const libc = tool({
  description:
    "CTF libc 计算器：记录 leak，支持 provided/local/remote libc 假设，计算 libc base、system、/bin/sh、hooks、one_gadget 地址，并写入 .ctf/state.json。",
  args: {
    binary: z.string().optional().describe("可选 ELF binary；assumption=local 且未提供 libc 时用 ldd 推断本地 libc"),
    libc: z.string().optional().describe("libc.so 路径；支持绝对路径或相对 session directory"),
    assumption: z.enum(["provided", "local", "remote"]).optional().describe("libc 来源假设：provided/local/remote；默认按参数推断"),
    leaks: z
      .array(
        z.object({
          symbol: z.string().describe("泄露符号名，例如 puts、__libc_start_main、__libc_start_main+243"),
          address: z.string().describe("泄露出的运行时地址，例如 0x7ffff7a5e5f0"),
          offset: z.string().optional().describe("泄露地址相对 symbol 的附加偏移，例如 243 或 0xf"),
          note: z.string().optional().describe("leak 来源说明"),
        }),
      )
      .optional()
      .describe("leak 列表"),
    base: z.string().optional().describe("已知 libc base；提供后直接用于地址计算"),
    oneGadget: z.boolean().optional().describe("是否调用 one_gadget，默认 true"),
    onlineLookup: z.boolean().optional().describe("本地/provided libc 不匹配或 remote 未知时是否自动查询 libc.rip，默认 true"),
    python: z.string().optional().describe("Python 解释器，默认 python3"),
    timeoutMs: z.number().int().positive().max(MAX_TIMEOUT_MS).optional(),
  },
  async execute(args, ctx) {
    const timeoutMs = clampTimeout(args.timeoutMs)
    const python = args.python?.trim() || "python3"
    const binary = args.binary ? await selectPwnBinary(args.binary, ctx) : undefined
    let libcPath = resolveReadableFile(args.libc, ctx.directory)
    const assumption = args.assumption ?? (libcPath ? "provided" : binary ? "local" : "remote")
    const leaks = args.leaks ?? []
    const leakSymbols = leaks.map((leak) => parseSymbolExpr(leak.symbol).name)

    if (binary) await requestPermission(ctx, "ctf_libc", binary, { binary, libc: libcPath, assumption })
    if (libcPath) await requestPermission(ctx, "ctf_libc", libcPath, { binary, libc: libcPath, assumption })
    ctx.metadata({ title: "CTF libc", metadata: { binary, libc: libcPath, assumption } })

    const commandResults = []
    if (!libcPath && assumption === "local" && binary) {
      const inferred = await inferLocalLibc(binary, timeoutMs)
      commandResults.push(inferred.result)
      if (inferred.path && existsSync(inferred.path)) libcPath = inferred.path
    }

    let info: LibcInfo | undefined
    if (libcPath) {
      const infoResult = await runCommand(dirname(libcPath), {
        label: "pwntools libc symbols",
        command: [python, "-c", libcInfoProgram(libcPath, leakSymbols)],
        timeoutMs,
        maxOutput: 60_000,
      })
      commandResults.push(infoResult)
      if (infoResult.exitCode === 0 && infoResult.stdout.trim()) {
        try {
          info = JSON.parse(infoResult.stdout.trim()) as LibcInfo
        } catch {
          info = undefined
        }
      }
    }

    const baseArg = parseAddress(args.base)
    const baseCandidates: Array<{ leak: LeakInput; base: bigint; aligned: boolean }> = []
    if (info) {
      for (const leak of leaks) {
        const parsed = parseSymbolExpr(leak.symbol)
        const symbolOffset = info.symbols[parsed.name]
        if (symbolOffset === undefined) continue
        const leaked = parseAddress(leak.address)
        if (leaked === undefined) continue
        const explicitOffset = parseAddress(leak.offset)
        const addend = explicitOffset ?? parsed.addend
        const base = leaked - BigInt(symbolOffset) - addend
        baseCandidates.push({ leak, base, aligned: (base & 0xfffn) === 0n })
      }
    }
    const selectedBase = baseArg ?? baseCandidates.find((item) => item.aligned)?.base ?? baseCandidates[0]?.base
    const hasAlignedBase = baseCandidates.some((item) => item.aligned)
    const shouldLookupRemote =
      args.onlineLookup !== false &&
      leaks.length > 0 &&
      baseArg === undefined &&
      (!libcPath || assumption === "remote" || (baseCandidates.length > 0 && !hasAlignedBase))
    let remoteLookup: RemoteLibcLookup | undefined
    if (shouldLookupRemote) {
      await requestPermission(ctx, "ctf_libc", "https://libc.rip/api/find", {
        assumption,
        leakCount: leaks.length,
        reason: !libcPath ? "unknown-libc" : "local-libc-mismatch",
      })
      remoteLookup = await queryLibcRip(leaks, timeoutMs)
    }

    let oneGadgetResult
    let oneGadgets: bigint[] = []
    if (libcPath && args.oneGadget !== false) {
      oneGadgetResult = await runCommand(dirname(libcPath), {
        label: "one_gadget",
        command: ["one_gadget", "-r", libcPath],
        timeoutMs,
        maxOutput: 30_000,
      })
      commandResults.push(oneGadgetResult)
      if (oneGadgetResult.exitCode === 0) oneGadgets = parseOneGadgetOffsets(oneGadgetResult.stdout)
    }

    const ws = await ensureCtfWorkspace(ctx)
    const stateRaw = await readFile(ws.state, "utf8").catch(() => "{}")
    const state = parseState(stateRaw)
    const resolved = {
      system:
        selectedBase !== undefined && info?.symbols.system !== undefined ? hex(selectedBase + BigInt(info.symbols.system)) : undefined,
      binsh: selectedBase !== undefined && info?.binsh !== undefined ? hex(selectedBase + BigInt(info.binsh)) : undefined,
      one_gadget:
        selectedBase !== undefined
          ? oneGadgets.slice(0, 40).map((offset) => ({ offset: hex(offset), address: hex(selectedBase + offset) }))
          : oneGadgets.slice(0, 40).map((offset) => ({ offset: hex(offset) })),
    }
    state.libc = {
      updatedAt: new Date().toISOString(),
      assumption,
      binary,
      libc: libcPath,
      base: hex(selectedBase),
      leaks,
      baseCandidates: baseCandidates.map((item) => ({
        symbol: item.leak.symbol,
        address: item.leak.address,
        base: hex(item.base),
        aligned: item.aligned,
      })),
      remoteCandidates: remoteLookup?.candidates.slice(0, 40),
      resolved,
    }
    await writeFile(ws.state, JSON.stringify(state, null, 2) + "\n")

    await appendRun(ctx, {
      type: "libc",
      assumption,
      binary,
      libc: libcPath,
      base: hex(selectedBase),
      leakCount: leaks.length,
      oneGadgetCount: oneGadgets.length,
    })
    await writeNote(ctx, {
      category: "pwn",
      title: `libc ${hex(selectedBase) ?? assumption}`,
      content: [
        `assumption: ${assumption}`,
        binary ? `binary: ${binary}` : "",
        libcPath ? `libc: ${libcPath}` : "libc: 未确定",
        selectedBase !== undefined ? `base: ${hex(selectedBase)}` : "",
      ].filter(Boolean).join("\n"),
      evidence: [
        `Leaks:\n${formatLeaks(leaks)}`,
        `Base candidates:\n${formatBaseCandidates(baseCandidates)}`,
        shouldLookupRemote ? `Remote libc candidates:\n${formatRemoteLibcLookup(remoteLookup, leaks)}` : "",
        `Resolved:\n${formatResolved({ base: selectedBase, info, oneGadgets })}`,
      ].filter(Boolean).join("\n\n"),
      next: selectedBase !== undefined
        ? "把已解析的 system、/bin/sh 或 one_gadget 地址填入 exploit，先本地复测。"
        : remoteLookup?.candidates.length
          ? "从 Remote libc 候选中选择匹配项，下载/提供 libc.so 后重跑；或直接使用候选里计算出的 system/bin_sh 做远程验证。"
          : "提供 libc 路径或更多 leak 后重跑 ctf_libc；remote 场景可先确认 BuildID/libc 版本。",
      tags: ["pwn", "libc"],
    })

    return {
      title: "CTF libc",
      output: [
        section("假设", [`assumption: ${assumption}`, binary ? `binary: ${binary}` : "", libcPath ? `libc: ${libcPath}` : "libc: 未确定"]),
        section("Leaks", formatLeaks(leaks)),
        section("Base 候选", formatBaseCandidates(baseCandidates)),
        shouldLookupRemote ? section("Remote libc 候选 (libc.rip)", formatRemoteLibcLookup(remoteLookup, leaks)) : "",
        section("解析结果", formatResolved({ base: selectedBase, info, oneGadgets })),
        section("状态文件", relative(ctx.worktree, ws.state) || ws.state),
        commandResults.length ? section("命令摘要", formatCommands(commandResults)) : "",
        !libcPath && assumption === "remote"
          ? section("Remote libc 提示", "当前按 remote libc 未知处理：已记录 leak；如 Remote libc 候选存在，可先选候选下载 libc.so 后重跑。")
          : "",
        libcPath && baseCandidates.length > 0 && !hasAlignedBase
          ? section("libc 匹配警告", "当前 libc 计算出的 base 未 page aligned，通常说明本地/provided libc 与远程不匹配；优先查看 Remote libc 候选。")
          : "",
        info ? "" : libcPath ? section("libc 解析警告", "pwntools 未能解析 libc JSON 输出；检查 python/pwntools 或 libc 文件。") : "",
        oneGadgetResult && oneGadgetResult.exitCode !== 0
          ? section("one_gadget", "one_gadget 不可用或执行失败；system('/bin/sh') 路径不受影响。")
          : "",
        selectedBase !== undefined && resolved.system && resolved.binsh
          ? section("ret2libc 常用值", code(`libc_base = ${hex(selectedBase)}\nsystem = ${resolved.system}\nbin_sh = ${resolved.binsh}`))
          : "",
      ].join("\n"),
      metadata: { assumption, binary, libc: libcPath, base: hex(selectedBase), resolved, remoteCandidates: remoteLookup?.candidates },
    }
  },
})
