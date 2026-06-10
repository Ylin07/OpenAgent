import { Context, Effect, Layer } from "effect"

import { InstanceState } from "@/effect/instance-state"

import PROMPT_DEFAULT from "./prompt/default.txt"
import type { Provider } from "@/provider/provider"
import type { Agent } from "@/agent/agent"
import { Permission } from "@/permission"
import { Skill } from "@/skill"

const LANGUAGE_POLICY = [
  "重要语言策略：",
  "- 除非用户明确要求使用其他语言，否则用中文回复。",
  "- 如果模型或 provider 在 UI 中暴露 reasoning 或 thinking 文本，这些文本也必须使用中文。",
  "- 当用户使用中文时，不要用英文组织推理或思路。",
  "- 代码、命令、路径、API 名称、库名、标识符和引用的错误消息保持原始语言。",
].join("\n")

export function provider(_model: Provider.Model) {
  return [LANGUAGE_POLICY, PROMPT_DEFAULT]
}

export interface Interface {
  readonly environment: (model: Provider.Model) => Effect.Effect<string[]>
  readonly skills: (agent: Agent.Info) => Effect.Effect<string | undefined>
}

export class Service extends Context.Service<Service, Interface>()("@openagent/SystemPrompt") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const skill = yield* Skill.Service

    return Service.of({
      environment: Effect.fn("SystemPrompt.environment")(function* (model: Provider.Model) {
        const ctx = yield* InstanceState.context
        return [
          [
            `你由名为 ${model.api.id} 的模型驱动。准确模型 ID 是 ${model.providerID}/${model.api.id}`,
            `以下是你当前运行环境的一些有用信息：`,
            `<env>`,
            `  工作目录：${ctx.directory}`,
            `  Workspace 根目录：${ctx.worktree}`,
            `  当前目录是否是 git 仓库：${ctx.project.vcs === "git" ? "yes" : "no"}`,
            `  平台：${process.platform}`,
            `  今天日期：${new Date().toDateString()}`,
            `</env>`,
            `你是一个帮助用户完成软件工程任务的交互式 CLI 工具。请根据以下说明并使用可用工具协助用户。`,
            LANGUAGE_POLICY,
          ].join("\n"),
        ]
      }),

      skills: Effect.fn("SystemPrompt.skills")(function* (agent: Agent.Info) {
        if (Permission.disabled(["skill"], agent.permission).has("skill")) return

        const list = yield* skill.available(agent)

        return [
          "Skills 会为特定任务提供专门的指令和工作流。",
          "当任务匹配某个 skill 的描述时，使用 skill 工具加载它。",
          // the agents seem to ingest the information about skills a bit better if we present a more verbose
          // version of them here and a less verbose version in tool description, rather than vice versa.
          Skill.fmt(list, { verbose: true }),
        ].join("\n")
      }),
    })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(Skill.defaultLayer))

export * as SystemPrompt from "./system"
