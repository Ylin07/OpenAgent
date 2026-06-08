// @ts-nocheck

import { OpenAgent } from "@openagent-ai/core"
import { ReadTool } from "@openagent-ai/core/tools"

const openagent = OpenAgent.make({})

openagent.tool.add(ReadTool)

openagent.tool.add({
  name: "bash",
  schema: {
    type: "object",
    properties: {
      command: {
        type: "string",
        description: "The command to run.",
      },
    },
    required: ["command"],
  },
  execute(input, ctx) {},
})

openagent.auth.add({
  provider: "openai",
  type: "api",
  value: process.env.OPENAI_API_KEY,
})

openagent.agent.add({
  name: "build",
  permissions: [],
  model: {
    id: "gpt-5-5",
    provider: "openai",
    variant: "xhigh",
  },
})

const sessionID = await openagent.session.create({
  agent: "build",
})

openagent.subscribe((event) => {
  console.log(event)
})

await openagent.session.prompt({
  sessionID,
  text: "hey what is up",
})

await openagent.session.prompt({
  sessionID,
  text: "what is up with this",
  files: [
    {
      mime: "image/png",
      uri: "data:image/png;base64,xxxx",
    },
  ],
})

await openagent.session.wait()

console.log(await openagent.session.messages(sessionID))
