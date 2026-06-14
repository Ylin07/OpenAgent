import { createHash } from "node:crypto"
import { readFile } from "node:fs/promises"
import { dirname, join, relative } from "node:path"
import { fileURLToPath } from "node:url"
import { tool } from "@openagent-ai/plugin"
import { clip, code, requestPermission, section } from "./core.ts"
import { appendRun, challengeArgs, updateCtfState, writeNote } from "./workspace.ts"

const z = tool.schema

const DOCS_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "docs")

const TOPICS = {
  "general/index": {
    domain: "general",
    path: "INDEX.md",
    title: "CTF 总索引",
  },
  "pwn/index": {
    domain: "pwn",
    path: "PWN/index.md",
    title: "PWN 题型索引",
  },
  "pwn/stack-rop": {
    domain: "pwn",
    path: "PWN/stack-rop.md",
    title: "PWN 栈溢出与 ROP",
  },
  "pwn/format-string": {
    domain: "pwn",
    path: "PWN/format-string.md",
    title: "PWN 格式化字符串",
  },
  "pwn/heap-fsop": {
    domain: "pwn",
    path: "PWN/heap-fsop.md",
    title: "PWN 堆利用与 FSOP",
  },
  "pwn/advanced": {
    domain: "pwn",
    path: "PWN/advanced.md",
    title: "PWN 高级场景",
  },
  "reverse/index": {
    domain: "reverse",
    path: "REVERSE/index.md",
    title: "REVERSE 题型索引",
  },
  "reverse/basic-workflow": {
    domain: "reverse",
    path: "REVERSE/basic-workflow.md",
    title: "REVERSE 常规流程",
  },
  "reverse/algorithm-maze-vm": {
    domain: "reverse",
    path: "REVERSE/algorithm-maze-vm.md",
    title: "REVERSE 算法、迷宫与 VM",
  },
  "reverse/obfuscation-anti-debug-unpack": {
    domain: "reverse",
    path: "REVERSE/obfuscation-anti-debug-unpack.md",
    title: "REVERSE 混淆、反调试与脱壳",
  },
  "reverse/tools": {
    domain: "reverse",
    path: "REVERSE/tools.md",
    title: "REVERSE 工具与自动化",
  },
} as const

type Topic = keyof typeof TOPICS

function topicKey(domain: string, topic: string): Topic {
  const key = `${domain}/${topic}` as Topic
  if (!(key in TOPICS)) {
    throw new Error(`未知 CTF doc topic: ${key}. 可用 topic: ${Object.keys(TOPICS).join(", ")}`)
  }
  return key
}

function sha256(text: string) {
  return createHash("sha256").update(text).digest("hex")
}

export const doc = tool({
  description:
    "CTF 文档读取与确认工具：按白名单读取 .openagent/docs 中的 pwn/reverse 索引或专题，并把已读 topic 写入 .ctf/state.json。继续 exploit/solver 前优先使用本工具确认对应文档。",
  args: {
    domain: z.enum(["general", "pwn", "reverse"]).describe("文档领域"),
    topic: z
      .enum([
        "index",
        "stack-rop",
        "format-string",
        "heap-fsop",
        "advanced",
        "basic-workflow",
        "algorithm-maze-vm",
        "obfuscation-anti-debug-unpack",
        "tools",
      ])
      .describe("文档主题；domain=pwn 支持 index/stack-rop/format-string/heap-fsop/advanced；domain=reverse 支持 index/basic-workflow/algorithm-maze-vm/obfuscation-anti-debug-unpack/tools；domain=general 仅支持 index"),
    reason: z.string().optional().describe("为什么需要读取该文档，例如 format string 证据、heap 菜单证据、VM dispatcher 证据"),
    ...challengeArgs(),
  },
  async execute(args, ctx) {
    const key = topicKey(args.domain, args.topic)
    const info = TOPICS[key]
    const path = join(DOCS_ROOT, info.path)
    await requestPermission(ctx, "ctf_doc", path, { domain: args.domain, topic: args.topic, reason: args.reason })
    const text = await readFile(path, "utf8")
    const hash = sha256(text)
    const ws = await updateCtfState(
      ctx,
      (state) => {
        const docs = state.docs && typeof state.docs === "object" && !Array.isArray(state.docs) ? state.docs : {}
        state.docs = {
          ...docs,
          [key]: {
            path,
            title: info.title,
            reason: args.reason,
            sha256: hash,
            loadedAt: new Date().toISOString(),
          },
        }
        return state
      },
      args.challenge,
    )
    await appendRun(ctx, { type: "doc", topic: key, path, reason: args.reason, sha256: hash }, args.challenge)
    await writeNote(ctx, {
      category: "finding",
      title: `已读取文档 ${key}`,
      content: `文档: ${info.title}\n路径: ${relative(ctx.worktree || ctx.directory, path) || path}`,
      evidence: args.reason,
      next: "后续分析必须引用该文档中的检查清单和题型路线；若出现更具体证据，再调用 ctf_doc 读取对应专题。",
      tags: ["doc", args.domain, args.topic],
      challenge: args.challenge,
    })
    return {
      title: `CTF doc: ${key}`,
      output: [
        section("文档", [`topic: ${key}`, `title: ${info.title}`, `path: ${relative(ctx.worktree || ctx.directory, path) || path}`]),
        args.reason ? section("读取原因", args.reason) : "",
        section("内容", code(clip(text, 24_000))),
        section("状态", `已记录到 ${relative(ctx.worktree || ctx.directory, ws.state) || ws.state} 的 docs.${key}`),
      ].join("\n"),
      metadata: { topic: key, path, sha256: hash },
    }
  },
})
