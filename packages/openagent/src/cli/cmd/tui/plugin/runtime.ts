import type { JSX } from "solid-js"

type SlotProps = {
  children?: JSX.Element
  [key: string]: unknown
}

export async function init() {}

export async function dispose() {}

export function Slot(props: SlotProps): JSX.Element {
  return props.children
}

export * as TuiPluginRuntime from "./runtime"
