import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { getProxyForUrl } from "./proxy-env"

const proxyKeys = [
  "http_proxy",
  "HTTP_PROXY",
  "https_proxy",
  "HTTPS_PROXY",
  "all_proxy",
  "ALL_PROXY",
  "no_proxy",
  "NO_PROXY",
]

const saved = new Map<string, string | undefined>()

beforeEach(() => {
  saved.clear()
  for (const key of proxyKeys) {
    saved.set(key, process.env[key])
    delete process.env[key]
  }
})

afterEach(() => {
  for (const key of proxyKeys) {
    const value = saved.get(key)
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
})

describe("getProxyForUrl", () => {
  test("uses protocol-specific proxy variables", () => {
    process.env.HTTP_PROXY = "proxy.local:8080"

    expect(getProxyForUrl("http://example.com/path")).toBe("http://proxy.local:8080")
    expect(getProxyForUrl("https://example.com/path")).toBeUndefined()
  })

  test("falls back to all_proxy", () => {
    process.env.ALL_PROXY = "socks5://proxy.local:1080"

    expect(getProxyForUrl("https://example.com/path")).toBe("socks5://proxy.local:1080")
  })

  test("honors no_proxy host and port filters", () => {
    process.env.HTTP_PROXY = "http://proxy.local:8080"
    process.env.NO_PROXY = "example.com:80,.internal.local"

    expect(getProxyForUrl("http://example.com/path")).toBeUndefined()
    expect(getProxyForUrl("http://example.com:8080/path")).toBe("http://proxy.local:8080")
    expect(getProxyForUrl("http://api.internal.local/path")).toBeUndefined()
  })

  test("ignores invalid URLs", () => {
    process.env.HTTP_PROXY = "http://proxy.local:8080"

    expect(getProxyForUrl("not a url")).toBeUndefined()
  })
})
