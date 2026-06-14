export * as SystemContextBuiltIns from "./builtins"

import { DateTime, Effect, Layer, Schema } from "effect"
import { Location } from "../location"
import { SystemContext } from "./index"
import { InstructionContext } from "../instruction-context"
import { SystemContextRegistry } from "./registry"

const builtIns = Layer.effectDiscard(
  Effect.gen(function* () {
    const location = yield* Location.Service
    const registry = yield* SystemContextRegistry.Service
    const environment = [
      "<env>",
      `  工作目录：${location.directory}`,
      `  Workspace 根目录：${location.project.directory}`,
      `  当前目录是否是 git 仓库：${location.vcs?.type === "git" ? "是" : "否"}`,
      `  平台：${process.platform}`,
      "</env>",
    ].join("\n")
    const context = SystemContext.combine([
      SystemContext.make({
        key: SystemContext.Key.make("core/environment"),
        codec: Schema.toCodecJson(Schema.String),
        load: Effect.succeed(environment),
        baseline: (environment) => ["以下是你当前运行环境的一些有用信息：", environment].join("\n"),
        update: (_previous, environment) => ["你当前运行环境已更新为：", environment].join("\n"),
      }),
      SystemContext.make({
        key: SystemContext.Key.make("core/date"),
        codec: Schema.toCodecJson(Schema.String),
        load: DateTime.nowAsDate.pipe(
          Effect.map((date) =>
            [
              date.getFullYear(),
              String(date.getMonth() + 1).padStart(2, "0"),
              String(date.getDate()).padStart(2, "0"),
            ].join("-"),
          ),
        ),
        baseline: (date) => `今天日期：${date}`,
        update: (_previous, date) => `今天日期已更新为：${date}`,
      }),
    ])

    yield* registry.contribute({ key: SystemContext.Key.make("core/builtins"), load: Effect.succeed(context) })
  }),
)

export const layer = Layer.mergeAll(builtIns, InstructionContext.layer).pipe(
  Layer.provideMerge(SystemContextRegistry.layer),
)

export const locationLayer = layer
