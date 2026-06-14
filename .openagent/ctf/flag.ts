import { tool } from "@openagent-ai/plugin"
import { code, requestPermission, section } from "./core.ts"
import { appendRun, challengeArgs, writeNote } from "./workspace.ts"

const z = tool.schema

type Candidate = {
  value: string
  reason: string
  confidence: "high" | "medium" | "low"
}

const BRACED = /[A-Za-z0-9_-]{0,32}\{[^{}\r\n]{3,200}\}/g
const TOKEN = /\b(?:flag|ctf|key|token|secret)[-_:= ]+([A-Za-z0-9_@./+=:-]{8,160})\b/gi

function unique(list: Candidate[]) {
  const seen = new Set<string>()
  return list.filter((item) => {
    if (seen.has(item.value)) return false
    seen.add(item.value)
    return true
  })
}

function extractCandidates(text: string) {
  const out: Candidate[] = []
  for (const match of text.matchAll(BRACED)) {
    out.push({ value: match[0], reason: "braced flag-like pattern", confidence: "high" })
  }
  for (const match of text.matchAll(TOKEN)) {
    if (match[1]) out.push({ value: match[1], reason: "flag/token labeled value", confidence: "medium" })
  }
  for (const raw of text.match(/\b[A-Za-z0-9+/=]{16,240}\b/g) ?? []) {
    try {
      const decoded = Buffer.from(raw, "base64").toString("utf8")
      for (const match of decoded.matchAll(BRACED)) {
        out.push({ value: match[0], reason: `base64 decoded from ${raw.slice(0, 24)}...`, confidence: "high" })
      }
    } catch {
      // Ignore malformed base64-like strings.
    }
  }
  return unique(out).slice(0, 20)
}

export const flag = tool({
  description: "CTF flag 验证工具：从文本或候选值中提取/验证 flag，并写入 .ctf 状态。",
  args: {
    text: z.string().optional().describe("包含候选 flag 的输出、文件片段或响应文本"),
    candidate: z.string().optional().describe("已知候选 flag"),
    source: z.string().optional().describe("候选来源，例如命令、文件、URL、子 agent 输出"),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const haystack = [args.candidate, args.text].filter(Boolean).join("\n")
    if (!haystack.trim()) throw new Error("必须提供 text 或 candidate")
    await requestPermission(ctx, "ctf_flag", args.source ?? "candidate", {
      source: args.source,
      hasCandidate: Boolean(args.candidate),
    })
    const candidates = unique([
      ...(args.candidate ? [{ value: args.candidate, reason: "explicit candidate", confidence: "medium" as const }] : []),
      ...extractCandidates(haystack),
    ])
    const best = candidates.find((item) => item.confidence === "high") ?? candidates[0]
    await appendRun(
      ctx,
      {
        type: "flag",
        source: args.source,
        candidates: candidates.map((item) => ({ value: item.value, confidence: item.confidence, reason: item.reason })),
      },
      args.challenge,
    )
    if (best) {
      await writeNote(ctx, {
        category: "flag",
        title: `候选 flag: ${best.value}`,
        content: `置信度: ${best.confidence}\n原因: ${best.reason}\n来源: ${args.source ?? "unknown"}`,
        tags: ["flag", best.confidence],
        challenge: args.challenge,
      })
    }
    return {
      title: best ? `CTF flag: ${best.confidence}` : "CTF flag: none",
      output: best
        ? [
            section("最佳候选", `${best.value}\n置信度: ${best.confidence}\n原因: ${best.reason}`),
            section(
              "全部候选",
              candidates.map((item) => `- [${item.confidence}] ${item.value} (${item.reason})`).join("\n"),
            ),
          ].join("\n")
        : [section("结果", "没有发现明显 flag。"), section("输入摘要", code(haystack.slice(0, 2000)))].join("\n"),
      metadata: { found: Boolean(best), best: best?.value, confidence: best?.confidence, count: candidates.length },
    }
  },
})
