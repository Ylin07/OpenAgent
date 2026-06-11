import { Prompt, type PromptRef } from "@tui/component/prompt"
import { createEffect, createMemo, createSignal, For, onMount, Show } from "solid-js"
import { useSync } from "../context/sync"
import { Toast } from "../ui/toast"
import { useArgs } from "../context/args"
import { useRoute, useRouteData } from "@tui/context/route"
import { usePromptRef } from "../context/prompt"
import { useLocal } from "../context/local"
import { useEditorContext } from "@tui/context/editor"
import { useTerminalDimensions } from "@opentui/solid"
import { useTuiConfig } from "../context/tui-config"
import { selectedForeground, useTheme } from "@tui/context/theme"
import { HomeSessionDestinationProvider } from "./home/session-destination"
import { RGBA, TextAttributes } from "@opentui/core"
import { useDirectory } from "@tui/context/directory"
import { useDialog } from "../ui/dialog"
import { OPENAGENT_BASE_MODE, useBindings, useCommandShortcut, useOpenAgentKeymap } from "../keymap"
import { Locale } from "@/util/locale"

let once = false
const placeholder = {
  normal: ["Ask anything...", "Fix a bug in the codebase", "Explain this project"],
  shell: ["ls -la", "git status", "pwd"],
}

export function Home() {
  const sync = useSync()
  const routeNav = useRoute()
  const route = useRouteData("home")
  const promptRef = usePromptRef()
  const [promptRefSignal, setPromptRefSignal] = createSignal<PromptRef | undefined>()
  const args = useArgs()
  const local = useLocal()
  const editor = useEditorContext()
  const dimensions = useTerminalDimensions()
  const tuiConfig = useTuiConfig()
  const { theme } = useTheme()
  const directory = useDirectory()
  const dialog = useDialog()
  const keymap = useOpenAgentKeymap()
  const [selected, setSelected] = createSignal(0)
  const [homeMode, setHomeMode] = createSignal<"NORMAL" | "INSERT">("NORMAL")
  const [promptMode, setPromptMode] = createSignal<"normal" | "shell">("normal")
  const compact = createMemo(() => dimensions().width < 88)
  const model = createMemo(() => local.model.parsed())
  const sessionMode = createMemo(() => {
    if (promptMode() === "shell") return "Shell"
    return Locale.titlecase(local.agent.current()?.name ?? "build")
  })
  const sessionModeTone = createMemo(() => {
    if (promptMode() === "shell") return theme.primary
    return local.agent.color(local.agent.current()?.name ?? "build")
  })
  const paletteShortcut = useCommandShortcut("command.palette.show")
  const sessions = createMemo(() => sync.data.session.filter((s) => s.parentID === undefined))
  const recentSessions = createMemo(() =>
    sessions()
      .toSorted((a, b) => b.time.updated - a.time.updated)
      .slice(0, compact() ? 5 : 12),
  )
  const maxIndex = createMemo(() => Math.max(0, recentSessions().length - 1))
  const promptFocused = () => promptRefSignal()?.focused ?? false
  const workspace = createMemo(() => Locale.truncateMiddle(directory(), compact() ? 44 : 76))
  let sent = false

  const navigateSession = (index: number) => {
    const session = recentSessions()[index]
    if (session) routeNav.navigate({ type: "session", sessionID: session.id })
  }

  const focusPrompt = (input?: string) => {
    const prompt = promptRefSignal()
    if (!prompt) return
    if (input !== undefined && prompt.current.input === "") prompt.set({ input, parts: [] })
    prompt.focus()
    setHomeMode("INSERT")
  }

  useBindings(() => ({
    mode: OPENAGENT_BASE_MODE,
    enabled: () => route.type === "home" && dialog.stack.length === 0 && !promptFocused(),
    priority: 2,
    bindings: [
      {
        key: "j,down",
        desc: "Next session",
        group: "Home",
        cmd: () => {
          if (maxIndex() < 0) return
          setSelected((s) => (s >= maxIndex() ? 0 : s + 1))
        },
      },
      {
        key: "k,up",
        desc: "Previous session",
        group: "Home",
        cmd: () => {
          if (maxIndex() < 0) return
          setSelected((s) => (s <= 0 ? maxIndex() : s - 1))
        },
      },
      {
        key: "return",
        desc: "Open session",
        group: "Home",
        cmd: () => navigateSession(selected()),
      },
      {
        key: "s",
        desc: "Search sessions",
        group: "Home",
        cmd: () => keymap.dispatchCommand("session.list"),
      },
      {
        key: "i",
        desc: "Insert prompt",
        group: "Home",
        cmd: () => focusPrompt(),
      },
      {
        key: "/",
        desc: "Slash command",
        group: "Home",
        cmd: () => focusPrompt("/"),
      },
    ],
  }))

  useBindings(() => ({
    mode: OPENAGENT_BASE_MODE,
    enabled: () => route.type === "home" && dialog.stack.length === 0 && promptFocused(),
    priority: 3,
    bindings: [
      {
        key: "escape",
        desc: "Normal mode",
        group: "Home",
        cmd: () => {
          promptRefSignal()?.blur()
          setHomeMode("NORMAL")
        },
      },
    ],
  }))

  onMount(() => {
    editor.clearSelection()
  })

  const bind = (r: PromptRef | undefined) => {
    setPromptRefSignal(r)
    promptRef.set(r)
    if (once || !r) return
    if (route.prompt) {
      r.set(route.prompt)
      once = true
      return
    }
    if (!args.prompt) return
    r.set({ input: args.prompt, parts: [] })
    once = true
  }

  createEffect(() => {
    const r = promptRefSignal()
    if (sent) return
    if (!r) return
    if (!sync.ready || !local.model.ready) return
    if (!args.prompt) return
    if (r.current.input !== args.prompt) return
    sent = true
    r.submit()
  })

  createEffect(() => {
    if (selected() > maxIndex()) setSelected(maxIndex())
  })

  return (
    <HomeSessionDestinationProvider>
      <box flexGrow={1} backgroundColor={theme.background} flexDirection="column">
        <VimHomeStatusLine
          mode={homeMode()}
          left={`${sessionMode()} ${workspace()}`}
          right={`${model().provider}/${model().model}${sync.ready ? "" : " syncing"}`}
          tone={sessionModeTone()}
        />

        <box flexGrow={1} minHeight={0} paddingLeft={2} paddingRight={2}>
          <Show
            when={recentSessions().length > 0}
            fallback={
              <box flexGrow={1} alignItems="center" justifyContent="center">
                <text fg={theme.textMuted}>No recent sessions. Type to start a new one.</text>
              </box>
            }
          >
            <box flexGrow={1} minHeight={0} paddingTop={1} paddingBottom={1}>
              <box
                flexShrink={0}
                flexDirection="row"
                justifyContent="space-between"
                border={["bottom"]}
                borderColor={theme.borderSubtle}
                paddingBottom={1}
              >
                <text fg={theme.textMuted}>
                  buffer://sessions <span style={{ fg: theme.borderSubtle }}>({sessions().length})</span>
                </text>
                <text fg={theme.textMuted} wrapMode="none">
                  {selected() + 1}/{recentSessions().length}
                </text>
              </box>
              <box flexGrow={1} minHeight={0}>
                <For each={recentSessions()}>
                  {(session, index) => {
                    const isSelected = createMemo(() => index() === selected())
                    return (
                      <box
                        flexDirection="row"
                        justifyContent="space-between"
                        paddingLeft={1}
                        paddingRight={1}
                        paddingTop={0}
                        paddingBottom={0}
                        backgroundColor={isSelected() ? theme.backgroundElement : theme.background}
                        border={isSelected() ? ["left"] : []}
                        borderColor={theme.primary}
                        onMouseOver={() => setSelected(index())}
                        onMouseUp={() => navigateSession(index())}
                        flexShrink={0}
                      >
                        <box flexShrink={1} minWidth={0} flexDirection="row" gap={1}>
                          <text fg={isSelected() ? theme.primary : theme.textMuted} wrapMode="none">
                            {isSelected() ? ">" : " "} {String(index() + 1).padStart(2, "0")}
                          </text>
                          <text fg={isSelected() ? theme.primary : theme.text} wrapMode="none">
                            {Locale.truncate(session.title || "Untitled", compact() ? 34 : 60)}
                          </text>
                        </box>
                        <text fg={theme.textMuted} wrapMode="none" flexShrink={0}>
                          {Locale.todayTimeOrDateTime(session.time.updated)}
                        </text>
                      </box>
                    )
                  }}
                </For>
              </box>
            </box>
          </Show>
        </box>

        <box
          flexShrink={0}
          paddingLeft={2}
          paddingRight={2}
          paddingTop={1}
          paddingBottom={1}
          border={["top"]}
          borderColor={theme.borderSubtle}
          flexDirection="row"
          gap={2}
        >
          <text fg={sessionModeTone()} wrapMode="none">
            {sessionMode()}
          </text>
          <box flexGrow={1} minWidth={0}>
            <Prompt
              compact
              autoFocus={homeMode() === "INSERT"}
              ref={bind}
              onFocusChange={(focused) => setHomeMode(focused ? "INSERT" : "NORMAL")}
              onModeChange={setPromptMode}
              placeholders={placeholder}
            />
          </box>
        </box>

        <HomeShortcutHints mode={homeMode()} compact={compact()} paletteShortcut={paletteShortcut()} />

        <Toast />
      </box>
    </HomeSessionDestinationProvider>
  )
}

function HomeShortcutHints(props: { mode: "NORMAL" | "INSERT"; compact: boolean; paletteShortcut: string }) {
  const { theme } = useTheme()
  const normalHints = createMemo(() =>
    props.compact
      ? [
          ["up/down", "select"],
          ["enter", "open"],
          ["s", "search"],
          ["i", "input mode"],
        ]
      : [
          ["up/down", "select session"],
          ["enter", "open"],
          ["s", "search"],
          ["i", "input mode"],
          ["/", "slash command"],
          [props.paletteShortcut || "ctrl+p", "commands"],
        ],
  )
  const insertHints = createMemo(() =>
    props.compact
      ? [
          ["esc", "normal"],
          ["enter", "send"],
        ]
      : [
          ["esc", "normal mode"],
          ["enter", "send"],
          ["/", "slash command"],
          [props.paletteShortcut || "ctrl+p", "commands"],
        ],
  )
  const hints = createMemo(() => (props.mode === "INSERT" ? insertHints() : normalHints()))

  return (
    <box
      flexShrink={0}
      paddingLeft={2}
      paddingRight={2}
      paddingBottom={1}
      flexDirection="row"
      gap={2}
      flexWrap="wrap"
    >
      <For each={hints()}>
        {([key, label]) => (
          <text fg={theme.text}>
            {key} <span style={{ fg: theme.textMuted }}>{label}</span>
          </text>
        )}
      </For>
    </box>
  )
}

function VimHomeStatusLine(props: { mode: string; left: string; right: string; tone: RGBA }) {
  const { theme } = useTheme()
  const fg = createMemo(() => selectedForeground(theme, props.tone))
  return (
    <box
      flexShrink={0}
      height={1}
      flexDirection="row"
      justifyContent="space-between"
      paddingLeft={1}
      paddingRight={1}
      backgroundColor={props.tone}
    >
      <text fg={fg()} attributes={TextAttributes.BOLD} wrapMode="none">
        {props.mode} {props.left}
      </text>
      <text fg={fg()} wrapMode="none">
        {props.right}
      </text>
    </box>
  )
}
