export type SessionTab = {
  id: string
  title: string
}

export type SessionTabSource = {
  id: string
  title?: string | null
}

function titleFromSource(source: SessionTabSource | undefined, fallback?: string) {
  return source?.title || fallback || "Untitled"
}

export function upsertSessionTab(tabs: readonly SessionTab[], source: SessionTabSource): SessionTab[] {
  const existing = tabs.find((tab) => tab.id === source.id)
  const next = { id: source.id, title: titleFromSource(source, existing?.title) }
  if (!existing) return [...tabs, next]
  if (existing.title === next.title) return [...tabs]
  return tabs.map((tab) => (tab.id === next.id ? next : tab))
}

export function removeSessionTab(tabs: readonly SessionTab[], sessionID: string): SessionTab[] {
  return tabs.filter((tab) => tab.id !== sessionID)
}

export function refreshSessionTabs(
  tabs: readonly SessionTab[],
  sources: readonly SessionTabSource[],
  limit: number,
): SessionTab[] {
  const sourceByID = new Map(sources.map((source) => [source.id, source]))
  return tabs
    .map((tab) => ({
      id: tab.id,
      title: titleFromSource(sourceByID.get(tab.id), tab.title),
    }))
    .slice(0, limit)
}
