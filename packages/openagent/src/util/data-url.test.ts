import { describe, expect, test } from "bun:test"
import { decodeDataUrl } from "./data-url"

describe("decodeDataUrl", () => {
  test("decodes percent-encoded data URLs", () => {
    expect(decodeDataUrl("data:text/plain,hello%20world")).toBe("hello world")
  })

  test("decodes base64 data URLs", () => {
    expect(decodeDataUrl("data:text/plain;base64,aGVsbG8gd29ybGQ=")).toBe("hello world")
  })

  test("returns an empty string for invalid data URLs", () => {
    expect(decodeDataUrl("not-a-data-url")).toBe("")
  })
})
