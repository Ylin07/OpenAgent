import { describe, expect, test } from "bun:test"
import {
  parseGitHubRemote,
  parseRemoteRepositoryReference,
  parseRepositoryReference,
  validateRepositoryBranch,
} from "./repository"

describe("repository reference parsing", () => {
  test("parses GitHub owner/repo shorthand", () => {
    const parsed = parseRepositoryReference("anomalyco/openagent")

    expect(parsed).toMatchObject({
      host: "github.com",
      owner: "anomalyco",
      repo: "openagent",
      remote: "https://github.com/anomalyco/openagent.git",
      label: "anomalyco/openagent",
    })
  })

  test("parses scp-style git remotes without losing the original remote", () => {
    const parsed = parseRemoteRepositoryReference("git@github.com:anomalyco/openagent.git")

    expect(parsed).toMatchObject({
      host: "github.com",
      owner: "anomalyco",
      repo: "openagent",
      remote: "git@github.com:anomalyco/openagent.git",
    })
  })

  test("extracts owner and repo from GitHub remotes", () => {
    expect(parseGitHubRemote("https://github.com/anomalyco/openagent.git")).toEqual({
      owner: "anomalyco",
      repo: "openagent",
    })
    expect(parseGitHubRemote("https://gitlab.com/anomalyco/openagent.git")).toBeNull()
  })

  test("validates branch names", () => {
    expect(() => validateRepositoryBranch("feature/test-1")).not.toThrow()
    expect(() => validateRepositoryBranch("-bad")).toThrow()
    expect(() => validateRepositoryBranch("bad..branch")).toThrow()
    expect(() => validateRepositoryBranch("bad branch")).toThrow()
  })
})
