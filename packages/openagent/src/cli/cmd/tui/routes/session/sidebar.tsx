import { useProject } from "@tui/context/project"
import { useSync } from "@tui/context/sync"
import { createMemo, Show } from "solid-js"
import { useTheme } from "../../context/theme"
import { useTuiConfig } from "../../context/tui-config"
import { InstallationChannel, InstallationVersion } from "@openagent-ai/core/installation/version"

import { getScrollAcceleration } from "../../util/scroll"
import { WorkspaceLabel } from "../../component/workspace-label"

export function Sidebar(props: { sessionID: string; overlay?: boolean }) {
  const project = useProject()
  const sync = useSync()
  const { theme } = useTheme()
  const tuiConfig = useTuiConfig()
  const session = createMemo(() => sync.session.get(props.sessionID))
  const workspace = () => {
    const workspaceID = session()?.workspaceID
    if (!workspaceID) return
    return project.workspace.get(workspaceID)
  }
  const scrollAcceleration = createMemo(() => getScrollAcceleration(tuiConfig))

  return (
    <Show when={session()}>
      <box
        backgroundColor={theme.backgroundElement}
        width={42}
        height="100%"
        paddingTop={1}
        paddingBottom={1}
        paddingLeft={2}
        paddingRight={2}
        border={["left"]}
        borderColor={theme.borderSubtle}
        position={props.overlay ? "absolute" : "relative"}
      >
        <scrollbox
          flexGrow={1}
          scrollAcceleration={scrollAcceleration()}
          verticalScrollbarOptions={{
            trackOptions: {
              backgroundColor: theme.background,
              foregroundColor: theme.borderActive,
            },
          }}
        >
          <box flexShrink={0} gap={1} paddingRight={1}>
            <box
              paddingRight={1}
              paddingLeft={1}
              paddingTop={1}
              paddingBottom={1}
              backgroundColor={theme.backgroundPanel}
              border={["left"]}
              borderColor={theme.primary}
            >
              <text fg={theme.text}>
                <b>{session()!.title}</b>
              </text>
              <Show when={InstallationChannel !== "latest"}>
                <text fg={theme.textMuted}>{props.sessionID}</text>
              </Show>
              <Show when={session()!.workspaceID}>
                <text fg={theme.textMuted}>
                  <Show
                    when={workspace()}
                    fallback={<WorkspaceLabel type="unknown" name={session()!.workspaceID!} status="error" icon />}
                  >
                    {(item) => (
                      <WorkspaceLabel
                        type={item().type}
                        name={item().name}
                        status={project.workspace.status(item().id) ?? "error"}
                        icon
                      />
                    )}
                  </Show>
                </text>
              </Show>
              <Show when={session()!.share?.url}>
                <text fg={theme.textMuted}>{session()!.share!.url}</text>
              </Show>
            </box>
          </box>
        </scrollbox>

        <box flexShrink={0} gap={1} paddingTop={1} border={["top"]} borderColor={theme.borderSubtle}>
          <text fg={theme.textMuted}>
            <span style={{ fg: theme.success }}>•</span> <b>Open</b>
            <span style={{ fg: theme.text }}>
              <b>Code</b>
            </span>{" "}
            <span>{InstallationVersion}</span>
          </text>
        </box>
      </box>
    </Show>
  )
}
