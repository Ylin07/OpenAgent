import path from "path"

export * as App from "./app"

export type Name = "openagent" | "opencode"

function normalize(value: string | undefined) {
  if (!value) return ""
  return path.basename(value).replace(/\.(exe|cmd|js|ts)$/i, "").toLowerCase()
}

function detect(): Name {
  const explicit = process.env.OPENCODE_APP ?? process.env.OPENAGENT_APP
  if (explicit === "opencode" || explicit === "openagent") return explicit

  const candidates = [process.env.OPENCODE_BIN, process.env.OPENAGENT_BIN, process.argv[1], process.execPath]
  if (candidates.some((candidate) => normalize(candidate) === "opencode")) return "opencode"
  return "openagent"
}

export const name = detect()
export const envPrefix = name === "opencode" ? "OPENCODE" : "OPENAGENT"
export const configName = name
export const projectConfigDir = `.${name}`
export const displayName = name === "opencode" ? "opencode" : "OpenAgent"

export function envName(openagentKey: string) {
  if (name === "opencode" && openagentKey === "OPENAGENT") return "OPENCODE"
  if (name !== "opencode" || !openagentKey.startsWith("OPENAGENT_")) return openagentKey
  return "OPENCODE_" + openagentKey.slice("OPENAGENT_".length)
}

export function env(openagentKey: string) {
  return process.env[envName(openagentKey)]
}
