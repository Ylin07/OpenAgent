declare global {
  const OPENAGENT_VERSION: string
  const OPENAGENT_CHANNEL: string
}

export const InstallationVersion = typeof OPENAGENT_VERSION === "string" ? OPENAGENT_VERSION : "local"
export const InstallationChannel = typeof OPENAGENT_CHANNEL === "string" ? OPENAGENT_CHANNEL : "local"
export const InstallationLocal = InstallationChannel === "local"
