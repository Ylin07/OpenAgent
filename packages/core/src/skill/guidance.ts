export * as SkillGuidance from "./guidance"

import { Context, Effect, Layer, Schema } from "effect"
import { AgentV2 } from "../agent"
import { PermissionV2 } from "../permission"
import { PluginBoot } from "../plugin/boot"
import { SkillV2 } from "../skill"
import { SystemContext } from "../system-context/index"

const Summary = Schema.Struct({
  name: Schema.String,
  description: Schema.String,
})
type Summary = typeof Summary.Type

const render = (skills: ReadonlyArray<Summary>) =>
  [
    "Skills 会为特定任务提供专门的指令和工作流。",
    "当任务匹配某个 skill 的描述时，使用 skill 工具加载该 skill。",
    ...(skills.length === 0
      ? ["当前没有可用 skills。"]
      : [
          "<available_skills>",
          ...skills.flatMap((skill) => [
            "  <skill>",
            `    <name>${skill.name}</name>`,
            `    <description>${skill.description}</description>`,
            "  </skill>",
          ]),
          "</available_skills>",
        ]),
  ].join("\n")

export interface Interface {
  readonly load: (agent: AgentV2.Selection) => Effect.Effect<SystemContext.SystemContext>
}

export class Service extends Context.Service<Service, Interface>()("@openagent/v2/SkillGuidance") {}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const boot = yield* PluginBoot.Service
    const skills = yield* SkillV2.Service

    return Service.of({
      load: Effect.fn("SkillGuidance.load")(function* (selection) {
        yield* boot.wait()
        const agent = selection.info
        if (!agent) return SystemContext.empty
        const permitted = SkillV2.available(yield* skills.list(), agent)
        if (permitted.length === 0 && PermissionV2.evaluate("skill", "*", agent.permissions).effect === "deny")
          return SystemContext.empty
        const available = permitted
          .flatMap((skill) =>
            skill.description === undefined ? [] : [{ name: skill.name, description: skill.description }],
          )
          .toSorted((a, b) => a.name.localeCompare(b.name))
        return SystemContext.make({
          key: SystemContext.Key.make("core/skill-guidance"),
          codec: Schema.toCodecJson(Schema.Array(Summary)),
          load: Effect.succeed(available),
          baseline: render,
          update: (_previous, current) =>
            [
              "可用 skills 已变更。此列表会取代之前的可用 skills 列表。",
              render(current),
            ].join("\n"),
          removed: () => "Skill guidance 不再可用。不要使用之前列出的任何 skill。",
        })
      }),
    })
  }),
)

export const locationLayer = layer
