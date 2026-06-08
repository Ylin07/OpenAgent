/// <reference path="../markdown.d.ts" />

export * as SkillPlugin from "./skill"

import { Effect } from "effect"
import { PluginV2 } from "../plugin"
import { AbsolutePath } from "../schema"
import { SkillV2 } from "../skill"
import customizeOpenAgentContent from "./skill/customize-openagent.md" with { type: "text" }

export const CustomizeOpenAgentContent = customizeOpenAgentContent

export const Plugin = PluginV2.define({
  id: PluginV2.ID.make("skill"),
  effect: Effect.gen(function* () {
    const skill = yield* SkillV2.Service
    const transform = yield* skill.transform()

    yield* transform((editor) => {
      editor.source(
        new SkillV2.EmbeddedSource({
          type: "embedded",
          skill: new SkillV2.Info({
            name: "customize-openagent",
            description:
              "Use ONLY when the user is editing or creating openagent's own configuration: openagent.json, openagent.jsonc, files under .openagent/, or files under ~/.config/openagent/. Also use when creating or fixing openagent agents, subagents, skills, plugins, MCP servers, or permission rules. Do not use for the user's own application code, or for any project that is not configuring openagent itself.",
            location: AbsolutePath.make("/builtin/customize-openagent.md"),
            content: CustomizeOpenAgentContent,
          }),
        }),
      )
    })
  }),
})
