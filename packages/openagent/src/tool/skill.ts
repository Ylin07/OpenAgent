import path from "path"
import { pathToFileURL } from "url"
import { Effect, Schema } from "effect"
import * as Stream from "effect/Stream"
import { Ripgrep } from "@openagent-ai/core/filesystem/ripgrep"
import { Skill } from "../skill"
import * as Tool from "./tool"
import DESCRIPTION from "./skill.txt"
import { FSUtil } from "@openagent-ai/core/fs-util"

export const Parameters = Schema.Struct({
  name: Schema.String.annotate({ description: "available_skills 中的 skill 名称" }),
})

export const SkillTool = Tool.define(
  "skill",
  Effect.gen(function* () {
    const skill = yield* Skill.Service
    const rg = yield* Ripgrep.Service
    const fs = yield* FSUtil.Service

    return {
      description: DESCRIPTION,
      parameters: Parameters,
      execute: (params: Schema.Schema.Type<typeof Parameters>, ctx: Tool.Context) =>
        Effect.gen(function* () {
          const info = yield* skill
            .require(params.name)
            .pipe(Effect.catchTag("Skill.NotFoundError", (error) => Effect.die(new Error(error.message))))

          yield* ctx.ask({
            permission: "skill",
            patterns: [params.name],
            always: [params.name],
            metadata: {},
          })

          const dir = path.dirname(info.location)
          const base = pathToFileURL(dir).href
          const references = yield* Effect.forEach(
            info.references ?? [],
            (reference) =>
              Effect.gen(function* () {
                const resolved = path.resolve(dir, reference)
                const text = yield* fs.readFileStringSafe(resolved).pipe(Effect.orElseSucceed(() => ""))
                if (!text) return undefined
                return [`<reference path="${resolved}">`, text.trim(), "</reference>"].join("\n")
              }),
            { concurrency: 4 },
          )
          const limit = 10
          const files = yield* rg.files({ cwd: dir, follow: false, hidden: true, signal: ctx.abort }).pipe(
            Stream.filter((file) => !file.includes("SKILL.md")),
            Stream.map((file) => path.resolve(dir, file)),
            Stream.take(limit),
            Stream.runCollect,
            Effect.map((chunk) => [...chunk].map((file) => `<file>${file}</file>`).join("\n")),
          )

          return {
            title: `Loaded skill: ${info.name}`,
            output: [
              `<skill_content name="${info.name}">`,
              `# Skill: ${info.name}`,
              "",
              info.content.trim(),
              "",
              `Base directory for this skill: ${base}`,
              "Relative paths in this skill (e.g., scripts/, reference/) are relative to this base directory.",
              "Note: file list is sampled.",
              "",
              ...(references.length
                ? [
                    "<skill_references>",
                    "These reference files were declared by the skill and have already been loaded.",
                    ...references.filter((reference) => reference !== undefined),
                    "</skill_references>",
                    "",
                  ]
                : []),
              "<skill_files>",
              files,
              "</skill_files>",
              "</skill_content>",
            ].join("\n"),
            metadata: {
              name: info.name,
              dir,
            },
          }
        }).pipe(Effect.orDie),
    }
  }),
)
