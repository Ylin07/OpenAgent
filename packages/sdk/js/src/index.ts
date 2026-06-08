export * from "./client.js"
export * from "./server.js"

import { createOpenAgentClient } from "./client.js"
import { createOpenAgentServer } from "./server.js"
import type { ServerOptions } from "./server.js"

export async function createOpenAgent(options?: ServerOptions) {
  const server = await createOpenAgentServer({
    ...options,
  })

  const client = createOpenAgentClient({
    baseUrl: server.url,
  })

  return {
    client,
    server,
  }
}
