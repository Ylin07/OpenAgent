import type { EditorTraits } from "@opentui/core"

export type PromptMode = "normal" | "shell"

export interface PromptTraitsInput {
  mode: PromptMode
  autocompleteVisible: boolean
  captureTab?: boolean
}

export type PromptTraits = EditorTraits & {
  owner: "openagent"
  role: "prompt"
}

/**
 * Compute the textarea editor traits for the prompt.
 *
 * The OpenTUI managed textarea keymap owns `traits.suspend`. Prompt traits
 * only expose capture/status metadata so focus changes cannot unsuspend the
 * keymap-managed editor mappings.
 */
export function computePromptTraits(input: PromptTraitsInput): PromptTraits {
  const captureTab = input.captureTab ?? true
  const capture =
    input.mode === "normal"
      ? input.autocompleteVisible
        ? (["escape", "navigate", "submit", "tab"] as const)
        : captureTab
          ? (["tab"] as const)
          : undefined
      : undefined
  return {
    capture,
    status: input.mode === "shell" ? "SHELL" : undefined,
    owner: "openagent",
    role: "prompt",
  }
}
