import { describe, expect, test } from "bun:test"
import { refreshSessionTabs, removeSessionTab, upsertSessionTab, type SessionTab } from "./session-tabs"

describe("session tabs", () => {
  test("adding a tab keeps the existing current tab", () => {
    const tabs = upsertSessionTab([{ id: "a", title: "Alpha" }], { id: "b", title: "Beta" })

    expect(tabs).toEqual([
      { id: "a", title: "Alpha" },
      { id: "b", title: "Beta" },
    ])
  })

  test("switching data sources does not drop previously opened tabs", () => {
    const tabs: SessionTab[] = [
      { id: "a", title: "Alpha" },
      { id: "b", title: "Beta" },
    ]

    expect(refreshSessionTabs(tabs, [{ id: "b", title: "Beta updated" }], 6)).toEqual([
      { id: "a", title: "Alpha" },
      { id: "b", title: "Beta updated" },
    ])
  })

  test("remounting on a newly active tab preserves existing tabs", () => {
    const persisted: SessionTab[] = [
      { id: "b", title: "Beta" },
      { id: "a", title: "Alpha" },
    ]

    expect(upsertSessionTab(persisted, { id: "a" })).toEqual([
      { id: "b", title: "Beta" },
      { id: "a", title: "Alpha" },
    ])
  })

  test("upserting an existing tab updates its title without reordering", () => {
    const tabs = upsertSessionTab(
      [
        { id: "a", title: "Alpha" },
        { id: "b", title: "Beta" },
      ],
      { id: "a", title: "Alpha updated" },
    )

    expect(tabs).toEqual([
      { id: "a", title: "Alpha updated" },
      { id: "b", title: "Beta" },
    ])
  })

  test("closing a tab only removes that tab", () => {
    expect(
      removeSessionTab(
        [
          { id: "a", title: "Alpha" },
          { id: "b", title: "Beta" },
        ],
        "a",
      ),
    ).toEqual([{ id: "b", title: "Beta" }])
  })
})
