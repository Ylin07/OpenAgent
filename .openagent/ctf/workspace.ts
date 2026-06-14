import { mkdir, readFile, readdir, writeFile } from "node:fs/promises"
import { existsSync } from "node:fs"
import { createHash } from "node:crypto"
import { join, relative } from "node:path"
import { tool, type ToolContext } from "@openagent-ai/plugin"
import { clip, code, normalizePath, requestPermission, section } from "./core.ts"

const z = tool.schema
const CURRENT_CHALLENGE = "current-challenge"

type NoteInput = {
  category: string
  title: string
  content: string
  tags?: string[]
  evidence?: string
  next?: string
  challenge?: string
}

type CtfWorkspace = {
  root: string
  baseRoot: string
  artifacts: string
  notes: string
  runs: string
  state: string
  challenge?: string
  challengeSlug?: string
}

export type CtfState = Record<string, unknown>

export function ctfRoot(ctx: ToolContext) {
  return normalizePath(".ctf", ctx)
}

function challengeSlug(input: string) {
  const raw = input.trim()
  const slug = raw
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80)
  const hash = createHash("sha256").update(raw).digest("hex").slice(0, 8)
  return `${slug || "challenge"}-${hash}`
}

export function challengeArgs() {
  return {
    challenge: z
      .string()
      .optional()
      .describe("可选题目名；传入后缓存到 .ctf/challenges/<challenge>/，并设为当前题目；省略时使用 .ctf/current-challenge"),
  }
}

async function currentChallenge(baseRoot: string) {
  const raw = await readFile(join(baseRoot, CURRENT_CHALLENGE), "utf8").catch(() => "")
  return raw.trim() || undefined
}

async function setCurrentChallenge(baseRoot: string, challenge: string) {
  await mkdir(baseRoot, { recursive: true })
  await writeFile(join(baseRoot, CURRENT_CHALLENGE), `${challenge}\n`)
}

export async function ensureCtfWorkspace(ctx: ToolContext, challenge?: string): Promise<CtfWorkspace> {
  const baseRoot = ctfRoot(ctx)
  const explicitChallenge = challenge?.trim() || undefined
  if (explicitChallenge) await setCurrentChallenge(baseRoot, explicitChallenge)
  const normalizedChallenge = explicitChallenge ?? (await currentChallenge(baseRoot))
  const slug = normalizedChallenge ? challengeSlug(normalizedChallenge) : undefined
  const root = slug ? join(baseRoot, "challenges", slug) : baseRoot
  const artifacts = join(root, "artifacts")
  await mkdir(artifacts, { recursive: true })
  return {
    root,
    baseRoot,
    artifacts,
    notes: join(root, "notes.md"),
    runs: join(root, "runs.jsonl"),
    state: join(root, "state.json"),
    challenge: normalizedChallenge,
    challengeSlug: slug,
  }
}

async function append(path: string, content: string) {
  const previous = await readFile(path, "utf8").catch(() => "")
  await writeFile(path, previous + content)
}

export async function readCtfState(ctx: ToolContext, challenge?: string): Promise<CtfState> {
  const ws = await ensureCtfWorkspace(ctx, challenge)
  const raw = await readFile(ws.state, "utf8").catch(() => "")
  if (!raw.trim()) return {}
  try {
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

export async function writeCtfState(ctx: ToolContext, state: CtfState, challenge?: string) {
  const ws = await ensureCtfWorkspace(ctx, challenge)
  await writeFile(ws.state, JSON.stringify(state, null, 2) + "\n")
  return ws
}

export async function updateCtfState(
  ctx: ToolContext,
  update: (state: CtfState) => CtfState | void,
  challenge?: string,
) {
  const state = await readCtfState(ctx, challenge)
  const next = update(state) ?? state
  return await writeCtfState(ctx, next, challenge)
}

export async function assertRequiredDocsLoaded(ctx: ToolContext, domain: "pwn" | "reverse", challenge?: string) {
  const state = await readCtfState(ctx, challenge)
  const requiredDocs = state.requiredDocs && typeof state.requiredDocs === "object" ? state.requiredDocs : {}
  const required = Array.isArray((requiredDocs as Record<string, unknown>)[domain])
    ? ((requiredDocs as Record<string, unknown>)[domain] as Array<Record<string, unknown>>)
    : []
  if (!required.length) return

  const docs = state.docs && typeof state.docs === "object" ? (state.docs as Record<string, unknown>) : {}
  const missing = required
    .map((item) => ({
      domain: typeof item.domain === "string" ? item.domain : domain,
      topic: typeof item.topic === "string" ? item.topic : undefined,
      reason: typeof item.reason === "string" ? item.reason : undefined,
    }))
    .filter((item): item is { domain: string; topic: string; reason?: string } => Boolean(item.topic))
    .filter((item) => docs[`${item.domain}/${item.topic}`] === undefined)

  if (!missing.length) return

  const commands = missing
    .map((item) => `ctf_doc domain="${item.domain}" topic="${item.topic}"${item.reason ? ` reason="${item.reason.replaceAll('"', "'")}"` : ""}`)
    .join("\n")
  throw new Error(`BLOCKED: 必须先读取 required docs。\n${commands}`)
}

export async function appendRun(ctx: ToolContext, event: Record<string, unknown>, challenge?: string) {
  const ws = await ensureCtfWorkspace(ctx, challenge)
  await append(
    ws.runs,
    JSON.stringify({
      time: new Date().toISOString(),
      agent: ctx.agent,
      challenge: ws.challenge,
      ...event,
    }) + "\n",
  )
}

export async function writeNote(ctx: ToolContext, input: NoteInput) {
  const ws = await ensureCtfWorkspace(ctx, input.challenge)
  const tags = input.tags?.length ? `\n- tags: ${input.tags.join(", ")}` : ""
  const evidence = input.evidence ? `\n\n证据:\n${input.evidence.trim()}` : ""
  const next = input.next ? `\n\n下一步:\n${input.next.trim()}` : ""
  const entry = [
    `\n## ${new Date().toISOString()} [${input.category}] ${input.title}`,
    ws.challenge ? `题目: ${ws.challenge}\n` : "",
    `${input.content.trim()}${tags}${evidence}${next}`,
    "",
  ].join("\n")
  await append(ws.notes, entry)
  await appendRun(
    ctx,
    {
      type: "note",
      category: input.category,
      title: input.title,
      tags: input.tags ?? [],
    },
    input.challenge,
  )
  return ws
}

export const note = tool({
  description: "记录 CTF 解题状态到 .ctf/notes.md，并把事件写入 .ctf/runs.jsonl。用于事实、假设、证据、下一步和 flag 线索。",
  args: {
    category: z
      .enum(["init", "web", "reverse", "pwn", "flag", "finding", "hypothesis", "todo", "summary"])
      .describe("笔记分类"),
    title: z.string().describe("简短标题"),
    content: z.string().describe("要记录的内容"),
    tags: z.array(z.string()).optional().describe("可选标签"),
    evidence: z.string().optional().describe("关键证据、命令输出摘要或响应差异"),
    next: z.string().optional().describe("下一步最小动作"),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const ws = await ensureCtfWorkspace(ctx, args.challenge)
    await requestPermission(ctx, "ctf_note", `${ws.root}/*`, { category: args.category, title: args.title })
    await writeNote(ctx, args)
    return {
      title: `CTF note: ${args.title}`,
      output: [`已记录到 ${ws.notes}`, section("内容", args.content), args.next ? section("下一步", args.next) : ""].join(
        "\n",
      ),
      metadata: { path: ws.notes, category: args.category },
    }
  },
})

export const status = tool({
  description:
    "读取 CTF 工作区状态：传 challenge 时切换到对应题目；省略时读取当前题目 .ctf/current-challenge，若不存在则读取旧版 .ctf。",
  args: {
    recentRuns: z.number().int().positive().max(50).optional().describe("显示最近多少条 runs.jsonl 事件，默认 10"),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const ws = await ensureCtfWorkspace(ctx, args.challenge)
    const notes = await readFile(ws.notes, "utf8").catch(() => "")
    const runsRaw = await readFile(ws.runs, "utf8").catch(() => "")
    const runs = runsRaw
      .trim()
      .split("\n")
      .filter(Boolean)
      .slice(-(args.recentRuns ?? 10))
      .join("\n")
    const artifacts = existsSync(ws.artifacts) ? await readdir(ws.artifacts).catch(() => []) : []
    const state = await readFile(ws.state, "utf8").catch(() => "")
    const challengeRoot = join(ws.baseRoot, "challenges")
    const challenges = args.challenge ? [] : existsSync(challengeRoot) ? await readdir(challengeRoot).catch(() => []) : []
    const rel = (path: string) => relative(ctx.worktree || ctx.directory, path) || path
    return {
      title: ws.challenge ? `CTF status: ${ws.challenge}` : "CTF status",
      output: [
        section("工作区", [
          ws.challenge ? `challenge: ${ws.challenge}` : "",
          ws.challengeSlug ? `challengeSlug: ${ws.challengeSlug}` : "",
          `root: ${rel(ws.root)}`,
          `notes: ${rel(ws.notes)}`,
          `runs: ${rel(ws.runs)}`,
          `state: ${rel(ws.state)}`,
        ]),
        challenges.length ? section("题目缓存", challenges.map((item) => `- ${item}`).join("\n")) : "",
        section("笔记", notes ? code(clip(notes, 12_000)) : "暂无笔记。"),
        section("结构化状态", state ? code(clip(state, 8_000)) : "暂无 state.json。"),
        section("最近事件", runs ? code(runs) : "暂无事件。"),
        section("Artifacts", artifacts.length ? artifacts.map((item) => `- ${item}`).join("\n") : "暂无 artifacts。"),
      ].join("\n"),
      metadata: {
        root: ws.root,
        challenge: ws.challenge,
        challengeSlug: ws.challengeSlug,
        notes: ws.notes,
        runs: ws.runs,
        state: ws.state,
        artifacts: artifacts.length,
        challenges: challenges.length,
      },
    }
  },
})
