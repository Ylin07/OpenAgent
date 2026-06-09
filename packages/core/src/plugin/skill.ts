/// <reference path="../markdown.d.ts" />

export * as SkillPlugin from "./skill"

import { Effect } from "effect"
import { PluginV2 } from "../plugin"
import { AbsolutePath } from "../schema"
import { SkillV2 } from "../skill"
import { App, type Name } from "../app"
import customizeContentTemplate from "./skill/customize-openagent.md" with { type: "text" }

function renderCustomizeContent(name: Name) {
  if (name === "openagent") return customizeContentTemplate
  return customizeContentTemplate.replaceAll("openagent", "opencode").replaceAll("OPENAGENT", "OPENCODE")
}

function customizeSkillDescription(name: Name) {
  const config = `${name}.json`
  const configc = `${name}.jsonc`
  const dir = `.${name}`
  return `Use ONLY when the user is editing or creating ${name}'s own configuration: ${config}, ${configc}, files under ${dir}/, or files under ~/.config/${name}/. Also use when creating or fixing ${name} agents, subagents, skills, plugins, MCP servers, or permission rules. Do not use for the user's own application code, or for any project that is not configuring ${name} itself.`
}

export const CustomizeSkillName = `customize-${App.name}`
export const CustomizeSkillDescription = customizeSkillDescription(App.name)
export const CustomizeSkillLocation = AbsolutePath.make(`/builtin/customize-${App.name}.md`)
export const CustomizeSkillContent = renderCustomizeContent(App.name)
export const CustomizeOpenCodeContent = renderCustomizeContent("opencode")
export const CustomizeOpenAgentContent = renderCustomizeContent("openagent")

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
            name: CustomizeSkillName,
            description: CustomizeSkillDescription,
            location: CustomizeSkillLocation,
            content: CustomizeSkillContent,
          }),
        }),
      )
    })
  }),
})
