import { describe, expect, test } from "bun:test"
import { join, split } from "./bom"

describe("BOM utilities", () => {
  test("split detects and removes a leading UTF-8 BOM marker", () => {
    expect(split("\uFEFFcontent")).toEqual({ bom: true, text: "content" })
    expect(split("content")).toEqual({ bom: false, text: "content" })
  })

  test("join normalizes existing markers before adding or removing one", () => {
    expect(join("\uFEFFcontent", false)).toBe("content")
    expect(join("\uFEFFcontent", true)).toBe("\uFEFFcontent")
  })
})
