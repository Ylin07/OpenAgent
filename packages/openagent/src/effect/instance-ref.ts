import { Context } from "effect"
import type { InstanceContext } from "@/project/instance-context"
import type { WorkspaceV2 } from "@openagent-ai/core/workspace"

export const InstanceRef = Context.Reference<InstanceContext | undefined>("~openagent/InstanceRef", {
  defaultValue: () => undefined,
})

export const WorkspaceRef = Context.Reference<WorkspaceV2.ID | undefined>("~openagent/WorkspaceRef", {
  defaultValue: () => undefined,
})
