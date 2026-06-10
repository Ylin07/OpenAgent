import { describe, expect, test } from "bun:test"
import { Binary } from "./binary"

const byID = (item: { id: string }) => item.id

describe("Binary", () => {
  test("search returns the existing item index", () => {
    expect(Binary.search([{ id: "a" }, { id: "c" }, { id: "e" }], "c", byID)).toEqual({
      found: true,
      index: 1,
    })
  })

  test("search returns the insertion index for missing items", () => {
    expect(Binary.search([{ id: "a" }, { id: "c" }, { id: "e" }], "d", byID)).toEqual({
      found: false,
      index: 2,
    })
  })

  test("insert keeps items sorted and mutates the input array", () => {
    const items = [{ id: "a" }, { id: "c" }]
    const result = Binary.insert(items, { id: "b" }, byID)

    expect(result).toBe(items)
    expect(items).toEqual([{ id: "a" }, { id: "b" }, { id: "c" }])
  })
})
