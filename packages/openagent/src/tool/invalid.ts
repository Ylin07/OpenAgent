import { Effect, Schema } from "effect"
import * as Tool from "./tool"

export const Parameters = Schema.Struct({
  tool: Schema.String,
  error: Schema.String,
})

export const InvalidTool = Tool.define(
  "invalid",
  Effect.succeed({
    description: "不要使用",
    parameters: Parameters,
    execute: (params: { tool: string; error: string }) =>
      Effect.succeed({
        title: "无效工具",
        output: `提供给工具的参数无效：${params.error}`,
        metadata: {},
      }),
  }),
)
