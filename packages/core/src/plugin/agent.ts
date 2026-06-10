export * as AgentPlugin from "./agent"

import path from "path"
import { Effect } from "effect"
import { AgentV2 } from "../agent"
import { Global } from "../global"
import { Location } from "../location"
import { PermissionV2 } from "../permission"
import { PluginV2 } from "../plugin"
import { App } from "../app"

const TRUNCATION_GLOB = path.join(Global.Path.data, "tool-output", "*")
const BUILD_SYSTEM =
  "你是 AI coding agent。通过检查 workspace、进行定向修改，并根据已配置权限使用工具，帮助用户完成软件工程任务。"

const PROMPT_EXPLORE = `你是文件搜索专家，擅长彻底导航和探索代码库。

你的优势：
- 使用 glob patterns 快速查找文件
- 使用强大的 regex patterns 搜索代码和文本
- 读取并分析文件内容

指南：
- 使用 Glob 做广泛文件模式匹配
- 使用 Grep 用 regex 搜索文件内容
- 当你知道需要读取的具体文件路径时，使用 Read
- 根据调用方指定的 thoroughness level 调整搜索方式
- 在最终回复中返回绝对文件路径
- 为保持清晰沟通，避免使用 emoji
- 不要创建任何文件，也不要运行会以任何方式修改用户系统状态的 bash 命令

高效完成用户的搜索请求，并清楚报告发现。`

const PROMPT_COMPACTION = `你是面向编码会话的锚定上下文摘要助手。

只总结提供给你的对话历史。最新几轮可能会在摘要之外原样保留，因此重点关注仍然影响后续工作的较早上下文。

如果 prompt 包含 <previous-summary> 块，将其视为当前锚定摘要。用新的历史更新它：保留仍然正确的细节，删除过时细节，并合并新事实。

始终严格遵循用户 prompt 要求的输出结构。保留每个 section；已知时保留准确文件路径和标识符；优先使用简短 bullet，而不是段落。

不要回答对话本身。不要提及你正在总结、压缩或合并上下文。使用与对话相同的语言回复。`

const PROMPT_TITLE = `你是标题生成器。你只输出会话标题，不输出其他内容。

<task>
生成一个简短标题，帮助用户之后找到这段对话。

遵循 <rules> 中的所有规则。
参考 <examples> 了解好标题应是什么样。
你的输出必须：
- 单行
- 不超过 50 个字符
- 不解释
</task>

<rules>
- 必须使用与被总结用户消息相同的语言
- 标题必须语法正确、读起来自然，不要堆砌词语
- 标题中绝不要包含工具名（例如 "read tool"、"bash tool"、"edit tool"）
- 聚焦用户之后需要找回的主要主题或问题
- 改变措辞方式，避免总是以“分析...”等重复模式开头
- 提到文件时，聚焦用户想对该文件做什么，而不只是说明用户分享了它
- 保持准确：技术术语、数字、文件名、HTTP codes
- 英文标题中移除：the、this、my、a、an
- 绝不要假设技术栈
- 绝不要使用工具
- 绝不要回答问题，只为对话生成标题
- 生成标题时，标题绝不要包含“summarizing”或“generating”
- 不要说你无法生成标题，也不要抱怨输入
- 即使输入很少，也始终输出有意义的内容
- 如果用户消息很短或偏闲聊（例如 "hello"、"lol"、"what's up"、"hey"）：
  -> 创建能反映用户语气或意图的标题（例如“问候”“快速确认”“轻松聊天”“开场消息”等）
</rules>

<examples>
"debug 500 errors in production" -> 调试生产环境 500 错误
"refactor user service" -> 重构 user service
"why is app.js failing" -> 排查 app.js 失败
"implement rate limiting" -> 实现 rate limiting
"how do I connect postgres to my API" -> Postgres API 连接
"best practices for React hooks" -> React hooks 最佳实践
"@src/auth.ts can you add refresh token support" -> Auth refresh token 支持
"@utils/parser.ts this is broken" -> Parser bug 修复
"look at @config.json" -> Config 审查
"@App.tsx add dark mode toggle" -> App dark mode toggle
</examples>`

const PROMPT_SUMMARY = `总结这段对话中完成的工作。写法类似 pull request 描述。

规则：
- 最多 2-3 句
- 描述已经完成的变更，而不是过程
- 不要提及运行测试、构建或其他验证步骤
- 不要解释用户要求了什么
- 使用第一人称书写（例如“我添加了...”“我修复了...”）
- 绝不要提问或添加新问题
- 如果对话以一个尚未回答的用户问题结束，保留该问题原文
- 如果对话以对用户的祈使句或请求结束（例如“现在请运行该命令并粘贴控制台输出”），始终在摘要中包含该确切请求`

export const Plugin = PluginV2.define({
  id: PluginV2.ID.make("agent"),
  effect: Effect.gen(function* () {
    const agent = yield* AgentV2.Service
    const location = yield* Location.Service
    const worktree = location.directory
    const whitelistedDirs = [TRUNCATION_GLOB, path.join(Global.Path.tmp, "*")]
    const readonlyExternalDirectory: PermissionV2.Ruleset = [
      { action: "external_directory", resource: "*", effect: "ask" },
      ...whitelistedDirs.map(
        (resource): PermissionV2.Rule => ({ action: "external_directory", resource, effect: "allow" }),
      ),
    ]
    const defaults: PermissionV2.Ruleset = [
      { action: "*", resource: "*", effect: "allow" },
      ...readonlyExternalDirectory,
      { action: "question", resource: "*", effect: "deny" },
      { action: "plan_enter", resource: "*", effect: "deny" },
      { action: "plan_exit", resource: "*", effect: "deny" },
      { action: "read", resource: "*", effect: "allow" },
      { action: "read", resource: "*.env", effect: "ask" },
      { action: "read", resource: "*.env.*", effect: "ask" },
      { action: "read", resource: "*.env.example", effect: "allow" },
    ]

    yield* agent.update((editor) => {
      editor.update(AgentV2.defaultID, (item) => {
        item.description = "默认 agent。根据已配置权限执行工具。"
        item.system ??= BUILD_SYSTEM
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_enter", resource: "*", effect: "allow" },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("plan"), (item) => {
        item.description = "计划模式。禁止所有编辑工具。"
        item.mode = "primary"
        item.permissions.push(
          ...PermissionV2.merge(defaults, [
            { action: "question", resource: "*", effect: "allow" },
            { action: "plan_exit", resource: "*", effect: "allow" },
            { action: "external_directory", resource: path.join(Global.Path.data, "plans", "*"), effect: "allow" },
            { action: "edit", resource: "*", effect: "deny" },
            { action: "edit", resource: path.join(App.projectConfigDir, "plans", "*.md"), effect: "allow" },
            {
              action: "edit",
              resource: path.relative(worktree, path.join(Global.Path.data, "plans", "*.md")),
              effect: "allow",
            },
          ]),
        )
      })

      editor.update(AgentV2.ID.make("general"), (item) => {
        item.description =
          "通用 agent，用于研究复杂问题并执行多步骤任务。使用此 agent 并行执行多个工作单元。"
        item.mode = "subagent"
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "todowrite", resource: "*", effect: "deny" }]))
      })

      editor.update(AgentV2.ID.make("explore"), (item) => {
        item.description =
          '专门用于探索代码库的快速 agent。当你需要按 pattern 快速查找文件（例如 "src/components/**/*.tsx"）、按关键词搜索代码（例如 "API endpoints"），或回答代码库相关问题（例如 "API endpoints 如何工作？"）时使用。调用此 agent 时，指定期望的 thoroughness level："quick" 表示基础搜索，"medium" 表示中等程度探索，"very thorough" 表示跨多个位置和命名约定的全面分析。'
        item.system = PROMPT_EXPLORE
        item.mode = "subagent"
        item.permissions.push(
          ...PermissionV2.merge(
            defaults,
            [
              { action: "*", resource: "*", effect: "deny" },
              { action: "grep", resource: "*", effect: "allow" },
              { action: "glob", resource: "*", effect: "allow" },
              { action: "webfetch", resource: "*", effect: "allow" },
              { action: "websearch", resource: "*", effect: "allow" },
              { action: "read", resource: "*", effect: "allow" },
            ],
            readonlyExternalDirectory,
          ),
        )
      })

      editor.update(AgentV2.ID.make("compaction"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_COMPACTION
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })

      editor.update(AgentV2.ID.make("title"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_TITLE
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })

      editor.update(AgentV2.ID.make("summary"), (item) => {
        item.mode = "primary"
        item.hidden = true
        item.system = PROMPT_SUMMARY
        item.permissions.push(...PermissionV2.merge(defaults, [{ action: "*", resource: "*", effect: "deny" }]))
      })
    })
  }),
})
