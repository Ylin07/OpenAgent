import { createStore, reconcile } from "solid-js/store"
import { createSimpleContext } from "./helper"
import type { PromptInfo } from "../component/prompt/history"
import { App } from "@openagent-ai/core/app"

export type HomeRoute = {
  type: "home"
  prompt?: PromptInfo
}

export type SessionRoute = {
  type: "session"
  sessionID: string
  prompt?: PromptInfo
}

export type PluginRoute = {
  type: "plugin"
  id: string
  data?: Record<string, unknown>
}

export type Route = HomeRoute | SessionRoute | PluginRoute

export const { use: useRoute, provider: RouteProvider } = createSimpleContext({
  name: "Route",
  init: (props: { initialRoute?: Route }) => {
    const [store, setStore] = createStore<Route>(
      props.initialRoute ??
        (App.env("OPENAGENT_ROUTE")
          ? JSON.parse(App.env("OPENAGENT_ROUTE")!)
          : {
              type: "home",
            }),
    )

    return {
      get data() {
        return store
      },
      navigate(route: Route) {
        setStore(reconcile(route))
      },
    }
  },
})

export type RouteContext = ReturnType<typeof useRoute>

export function useRouteData<T extends Route["type"]>(type: T) {
  const route = useRoute()
  return route.data as Extract<Route, { type: typeof type }>
}
