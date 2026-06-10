import { mkdir, readFile, readdir, writeFile } from "node:fs/promises"
import { existsSync } from "node:fs"
import { join, relative } from "node:path"
import { tool, type ToolContext } from "@openagent-ai/plugin"
import { clip, code, normalizePath, requestPermission, section } from "./core.ts"

const z = tool.schema

type NoteInput = {
  category: string
  title: string
  content: string
  tags?: string[]
  evidence?: string
  next?: string
}

export function ctfRoot(ctx: ToolContext) {
  return normalizePath(".ctf", ctx)
}

export async function ensureCtfWorkspace(ctx: ToolContext) {
  const root = ctfRoot(ctx)
  const artifacts = join(root, "artifacts")
  await mkdir(artifacts, { recursive: true })
  return {
    root,
    artifacts,
    notes: join(root, "notes.md"),
    runs: join(root, "runs.jsonl"),
    state: join(root, "state.json"),
  }
}

async function append(path: string, content: string) {
  const previous = await readFile(path, "utf8").catch(() => "")
  await writeFile(path, previous + content)
}

export async function appendRun(ctx: ToolContext, event: Record<string, unknown>) {
  const ws = await ensureCtfWorkspace(ctx)
  await append(
    ws.runs,
    JSON.stringify({
      time: new Date().toISOString(),
      agent: ctx.agent,
      ...event,
    }) + "\n",
  )
}

export async function writeNote(ctx: ToolContext, input: NoteInput) {
  const ws = await ensureCtfWorkspace(ctx)
  const tags = input.tags?.length ? `\n- tags: ${input.tags.join(", ")}` : ""
  const evidence = input.evidence ? `\n\n证据:\n${input.evidence.trim()}` : ""
  const next = input.next ? `\n\n下一步:\n${input.next.trim()}` : ""
  const entry = [
    `\n## ${new Date().toISOString()} [${input.category}] ${input.title}`,
    `${input.content.trim()}${tags}${evidence}${next}`,
    "",
  ].join("\n")
  await append(ws.notes, entry)
  await appendRun(ctx, {
    type: "note",
    category: input.category,
    title: input.title,
    tags: input.tags ?? [],
  })
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
  },
  async execute(args, ctx) {
    const ws = await ensureCtfWorkspace(ctx)
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
  description: "读取当前 CTF 工作区状态：.ctf/notes.md、runs.jsonl 尾部和 artifacts 列表。CTF agent 开始工作前应先调用。",
  args: {
    recentRuns: z.number().int().positive().max(50).optional().describe("显示最近多少条 runs.jsonl 事件，默认 10"),
  },
  async execute(args, ctx) {
    const ws = await ensureCtfWorkspace(ctx)
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
    const rel = (path: string) => relative(ctx.worktree || ctx.directory, path) || path
    return {
      title: "CTF status",
      output: [
        section("工作区", [`root: ${rel(ws.root)}`, `notes: ${rel(ws.notes)}`, `runs: ${rel(ws.runs)}`, `state: ${rel(ws.state)}`]),
        section("笔记", notes ? code(clip(notes, 12_000)) : "暂无笔记。"),
        section("结构化状态", state ? code(clip(state, 8_000)) : "暂无 state.json。"),
        section("最近事件", runs ? code(runs) : "暂无事件。"),
        section("Artifacts", artifacts.length ? artifacts.map((item) => `- ${item}`).join("\n") : "暂无 artifacts。"),
      ].join("\n"),
      metadata: { root: ws.root, notes: ws.notes, runs: ws.runs, state: ws.state, artifacts: artifacts.length },
    }
  },
})
