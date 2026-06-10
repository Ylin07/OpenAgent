import { describe, expect, test } from "bun:test"
import { base64Decode, base64Encode, checksum, sampledChecksum } from "./encode"

describe("encode utilities", () => {
  test("base64Encode creates URL-safe output and round-trips unicode text", () => {
    const encoded = base64Encode("hello / + = \u4e16\u754c")

    expect(encoded).not.toContain("+")
    expect(encoded).not.toContain("/")
    expect(encoded).not.toContain("=")
    expect(base64Decode(encoded)).toBe("hello / + = \u4e16\u754c")
  })

  test("checksum is stable and omits empty content", () => {
    expect(checksum("")).toBeUndefined()
    expect(checksum("same content")).toBe(checksum("same content"))
    expect(checksum("same content")).not.toBe(checksum("different content"))
  })

  test("sampledChecksum includes full content length when sampling large input", () => {
    const content = "a".repeat(128)

    expect(sampledChecksum(content, 32)?.startsWith("128:")).toBe(true)
  })
})
