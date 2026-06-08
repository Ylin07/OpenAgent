import { Layer } from "effect"
import { TuiConfig } from "./config/tui"
import { Npm } from "@openagent-ai/core/npm"
import { Observability } from "@openagent-ai/core/effect/observability"

export const CliLayer = Observability.layer.pipe(Layer.merge(TuiConfig.layer), Layer.provide(Npm.defaultLayer))
