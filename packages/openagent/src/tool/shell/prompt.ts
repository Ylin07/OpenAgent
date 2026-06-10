import { Schema } from "effect"
import DESCRIPTION from "./shell.txt"
import { PositiveInt } from "@openagent-ai/core/schema"
import { Global } from "@openagent-ai/core/global"
import { ShellID } from "./id"

const PS = new Set(["powershell", "pwsh"])
const CMD = new Set(["cmd"])

const descriptions = {
  bash: "用 5-10 个词清楚简洁地描述此命令的作用。示例：\n输入：ls\n输出：列出当前目录文件\n\n输入：git status\n输出：显示工作树状态\n\n输入：npm install\n输出：安装包依赖\n\n输入：mkdir foo\n输出：创建目录 'foo'",
  powershell:
    '用 5-10 个词清楚简洁地描述此命令的作用。示例：\n输入：Get-ChildItem -LiteralPath "."\n输出：列出当前目录\n\n输入：git status\n输出：显示工作树状态\n\n输入：npm install\n输出：安装包依赖\n\n输入：New-Item -ItemType Directory -Path "tmp"\n输出：创建目录 tmp',
  cmd: '用 5-10 个词清楚简洁地描述此命令的作用。示例：\n输入：dir\n输出：列出当前目录\n\n输入：if exist "package.json" type "package.json"\n输出：存在时打印 package.json\n\n输入：mkdir tmp\n输出：创建目录 tmp',
}

export type Limits = {
  maxLines: number
  maxBytes: number
}

export function parameterSchema(description: string) {
  return Schema.Struct({
    command: Schema.String.annotate({ description: "要执行的命令" }),
    timeout: Schema.optional(PositiveInt).annotate({ description: "可选 timeout，单位为 milliseconds" }),
    workdir: Schema.optional(Schema.String).annotate({
      description: `运行命令的工作目录。默认为当前目录。请使用此参数，而不是 'cd' 命令。`,
    }),
    description: Schema.String.annotate({ description }),
  })
}

export const Parameters = parameterSchema(descriptions.bash)
export type Parameters = Schema.Schema.Type<typeof Parameters>

function renderPrompt(template: string, values: Record<string, string>) {
  return template.replace(/\$\{(\w+)\}/g, (_, key: string) => {
    const value = values[key]
    if (value === undefined) throw new Error(`Missing shell prompt value: ${key}`)
    return value
  })
}

function shellDisplayName(name: string) {
  if (name === "pwsh") return "PowerShell (7+)"
  if (name === "powershell") return "Windows PowerShell (5.1)"
  if (name === "cmd") return "cmd.exe"
  return name
}

function powershellNotes(name: string) {
  if (name === "pwsh") {
    return `# PowerShell (7+) shell 说明
- 此跨平台 shell 支持 pipeline chain operators（\`&&\` 和 \`||\`）。
- 插值字符串使用双引号（\`"Hello $name"\`），逐字字符串使用单引号。
- 优先使用完整 cmdlet 名称，例如 \`Get-ChildItem\`、\`Set-Content\`、\`Remove-Item\` 和 \`New-Item\`，而不是 aliases。
- 使用 \`$(...)\` 表示 subexpressions。使用 \`@(...)\` 表示 array expressions。
- 调用路径中包含空格的 native executable 时，使用 call operator：\`& "path/to/exe" args\`。
- 使用 PowerShell backtick character 转义特殊字符。`
  }
  if (name === "powershell") {
    return `# Windows PowerShell (5.1) shell 说明
- 使用 \`cmd1; if ($?) { cmd2 }\` 串联有依赖关系的命令。
- 插值字符串使用双引号（\`"Hello $name"\`），逐字字符串使用单引号。
- 优先使用完整 cmdlet 名称，例如 \`Get-ChildItem\`、\`Set-Content\`、\`Remove-Item\` 和 \`New-Item\`，而不是 aliases。
- 使用 \`$(...)\` 表示 subexpressions。使用 \`@(...)\` 表示 array expressions。
- 调用路径中包含空格的 native executable 时，使用 call operator：\`& "path/to/exe" args\`。
- 使用 PowerShell backtick character 转义特殊字符。`
  }
  return ""
}

function chainGuidance(name: string) {
  if (name === "powershell") {
    return "如果命令相互依赖并且必须顺序运行，请避免在此 shell 中使用 '&&'，因为 Windows PowerShell (5.1) 不支持它。当后续命令必须依赖前面命令成功时，使用 PowerShell conditionals，例如 `cmd1; if ($?) { cmd2 }`。"
  }
  if (PS.has(name)) {
    return "如果命令相互依赖并且必须顺序运行，请在单个 bash tool call 中使用 '&&' 将它们串联起来（例如 `git add . && git commit -m \"message\" && git push`）。例如，如果一个操作必须在另一个操作开始前完成（如 Copy-Item 前的 New-Item、git 操作中 bash 前的 Write、或 git commit 前的 git add），请顺序运行这些操作。"
  }
  if (CMD.has(name)) {
    return "如果命令相互依赖并且必须顺序运行，请在单个 bash tool call 中使用 `&&` 将它们串联起来（例如 `mkdir out && dir out`）。例如，如果一个操作必须在另一个操作开始前完成，请顺序运行这些操作。"
  }
  return "如果命令相互依赖并且必须顺序运行，请在单个 Bash 调用中使用 '&&' 将它们串联起来（例如 `git add . && git commit -m \"message\" && git push`）。例如，如果一个操作必须在另一个操作开始前完成（如 cp 前的 mkdir、git 操作中 Bash 前的 Write、或 git commit 前的 git add），请顺序运行这些操作。"
}

function bashCommandSection(chain: string, limits: Limits, defaultTimeoutMs: number) {
  return `执行命令前，请遵循以下步骤：

1. 目录验证：
   - 如果命令会创建新目录或文件，先使用 \`ls\` 验证父目录存在且位置正确
   - 例如，运行 "mkdir foo/bar" 前，先使用 \`ls foo\` 检查 "foo" 存在且是预期父目录

2. 命令执行：
   - 对包含空格的文件路径，始终用双引号包裹（例如 rm "path with spaces/file.txt"）
   - 正确引用示例：
     - mkdir "/Users/name/My Documents"（正确）
     - mkdir /Users/name/My Documents（错误，会失败）
     - python "/path/with spaces/script.py"（正确）
     - python /path/with spaces/script.py（错误，会失败）
   - 确保正确引用后，执行命令。
   - 捕获命令输出。

用法说明：
  - command 参数必填。
  - 可以指定可选 timeout，单位为 milliseconds。如果未指定，命令会在 ${defaultTimeoutMs}ms 后超时。
  - 用 5-10 个词清楚简洁地描述命令作用会很有帮助。
  - 如果输出超过 ${limits.maxLines} 行或 ${limits.maxBytes} bytes，它会被截断，完整输出会写入文件。你可以使用 Read 配合 offset/limit 读取特定部分，或使用 Grep 搜索完整内容。不要使用 \`head\`、\`tail\` 或其他截断命令限制输出；完整输出已经会被捕获到文件，以便更精确搜索。

  - 除非明确要求，或这些命令对任务确实必要，否则避免在 Bash 中使用 \`find\`、\`grep\`、\`cat\`、\`head\`、\`tail\`、\`sed\`、\`awk\` 或 \`echo\` 命令。应始终优先使用这些命令对应的专用工具：
    - 文件搜索：使用 Glob（不要用 find 或 ls）
    - 内容搜索：使用 Grep（不要用 grep 或 rg）
    - 读取文件：使用 Read（不要用 cat/head/tail）
    - 编辑文件：使用 Edit（不要用 sed/awk）
    - 写入文件：使用 Write（不要用 echo >/cat <<EOF）
    - 沟通：直接输出文本（不要用 echo/printf）
  - 发出多个命令时：
    - 如果命令相互独立并可并行运行，在一条消息中发起多个 bash 工具调用。例如，如果需要运行 "git status" 和 "git diff"，就在一条消息中发送两个并行 bash 工具调用。
    - ${chain}
    - 只有在需要顺序运行命令但不关心前面命令是否失败时，才使用 ';'
    - 不要使用换行分隔命令（quoted strings 中的换行可以）
  - 避免使用 \`cd <directory> && <command>\`。改用 \`workdir\` 参数切换目录。
    <good-example>
    使用 workdir="/foo/bar"，命令为：pytest tests
    </good-example>
    <bad-example>
    cd /foo/bar && pytest tests
    </bad-example>`
}

function powershellCommandSection(
  name: string,
  chain: string,
  pathSep: string,
  limits: Limits,
  defaultTimeoutMs: number,
) {
  return `${powershellNotes(name)}

执行命令前，请遵循以下步骤：

1. 目录验证：
   - 如果命令会创建新目录或文件，先使用 \`Test-Path -LiteralPath <parent>\` 验证父目录存在且位置正确
   - 例如，创建 \`foo${pathSep}bar\` 前，先使用 \`Test-Path -LiteralPath "foo"\` 检查 \`foo\` 存在且是预期父目录

2. 命令执行：
   - 对包含空格的文件路径，始终用双引号包裹（例如 Remove-Item -LiteralPath "path with spaces${pathSep}file.txt"）
   - 正确引用示例：
     - New-Item -ItemType Directory -Path "My Documents"（正确）
     - New-Item -ItemType Directory -Path My Documents（错误，路径会被拆分）
     - & "path with spaces${pathSep}script.ps1"（正确）
     - path with spaces${pathSep}script.ps1（错误，路径会被拆分且不会被调用）
   - 确保正确引用后，执行命令。
   - 捕获命令输出。

用法说明：
  - command 参数必填。
  - 可以指定可选 timeout，单位为 milliseconds。如果未指定，命令会在 ${defaultTimeoutMs}ms 后超时。
  - 用 5-10 个词清楚简洁地描述命令作用会很有帮助。
  - 如果输出超过 ${limits.maxLines} 行或 ${limits.maxBytes} bytes，它会被截断，完整输出会写入文件。你可以使用 Read 配合 offset/limit 读取特定部分，或使用 Grep 搜索完整内容。不要使用 \`Select-Object -First\`、\`Select-Object -Last\` 或其他截断命令限制输出；完整输出已经会被捕获到文件，以便更精确搜索。

  - 除非明确要求，或这些 cmdlets 对任务确实必要，否则避免在 Shell 中使用 PowerShell 文件/内容 cmdlets。应始终优先使用这些命令对应的专用工具：
    - 文件搜索：使用 Glob（不要用 Get-ChildItem）
    - 内容搜索：使用 Grep（不要用 Select-String）
    - 读取文件：使用 Read（不要用 Get-Content）
    - 编辑文件：使用 Edit（不要用 Set-Content）
    - 写入文件：使用 Write（不要用 Set-Content/Out-File 或 here-strings）
    - 沟通：直接输出文本（不要用 Write-Output/Write-Host）
  - 发出多个命令时：
    - 如果命令相互独立并可并行运行，在一条消息中发起多个 bash 工具调用。例如，如果需要运行 "git status" 和 "git diff"，就在一条消息中发送两个并行 bash 工具调用。
    - ${chain}
    - 只有在需要顺序运行命令但不关心前面命令是否失败时，才使用 \`;\`
    - 不要使用换行分隔命令（quoted strings 中的换行可以）
  - 避免在命令内部切换目录。改用 \`workdir\` 参数切换目录。
    <good-example>
    使用 workdir="project${pathSep}subdir"，命令为：pytest tests
    </good-example>
    <bad-example>
    ${name === "powershell" ? `Set-Location -LiteralPath "project${pathSep}subdir"; if ($?) { pytest tests }` : `Set-Location -LiteralPath "project${pathSep}subdir" && pytest tests`}
    </bad-example>`
}

function cmdCommandSection(chain: string, limits: Limits, defaultTimeoutMs: number) {
  return `# cmd.exe shell 说明
- 对包含空格的路径使用双引号。
- 环境变量使用 %VAR%。
- 存在性检查使用 \`if exist\`。
- 从另一个 batch-style command 调用 batch files 时使用 \`call\`。

执行命令前，请遵循以下步骤：

1. 目录验证：
   - 如果命令会创建新目录或文件，先使用 \`if exist\` 验证父目录存在且位置正确
   - 例如，创建 \`foo\\bar\` 前，先使用 \`if exist "foo\\" dir "foo"\` 检查 \`foo\` 存在且是预期父目录

2. 命令执行：
   - 对包含空格的文件路径，始终用双引号包裹（例如 del "path with spaces\\file.txt"）
   - 正确引用示例：
     - mkdir "My Documents"（正确）
     - mkdir My Documents（错误，路径会被拆分）
     - call "path with spaces\\script.bat"（正确）
     - path with spaces\\script.bat（错误，路径会被拆分且无法正确调用）
   - 确保正确引用后，执行命令。
   - 捕获命令输出。

用法说明：
  - command 参数必填。
  - 可以指定可选 timeout，单位为 milliseconds。如果未指定，命令会在 ${defaultTimeoutMs}ms 后超时。
  - 用 5-10 个词清楚简洁地描述命令作用会很有帮助。
  - 如果输出超过 ${limits.maxLines} 行或 ${limits.maxBytes} bytes，它会被截断，完整输出会写入文件。你可以使用 Read 配合 offset/limit 读取特定部分，或使用 Grep 搜索完整内容。不要使用 \`more\` 或其他分页命令限制输出；完整输出已经会被捕获到文件，以便更精确搜索。

  - 除非明确要求，或这些命令对任务确实必要，否则避免在 Shell 中使用 cmd.exe 文件/内容命令。应始终优先使用这些命令对应的专用工具：
    - 文件搜索：使用 Glob（不要用 dir /s）
    - 内容搜索：使用 Grep（不要用 findstr）
    - 读取文件：使用 Read（不要用 type）
    - 编辑文件：使用 Edit（不要用 copy）
    - 写入文件：使用 Write（不要用 echo > file）
    - 沟通：直接输出文本（不要用 echo）
  - 发出多个命令时：
    - 如果命令相互独立并可并行运行，在一条消息中发起多个 bash 工具调用。例如，如果需要运行 "dir" 和 "where cmd"，就在一条消息中发送两个并行 bash 工具调用。
    - ${chain}
    - 只有在需要顺序运行命令但不关心前面命令是否失败时，才使用 \`&\`
    - 不要使用换行分隔命令（quoted strings 中的换行可以）
  - 避免在命令内部切换目录。改用 \`workdir\` 参数切换目录。
    <good-example>
    使用 workdir="project\\subdir"，命令为：dir
    </good-example>
    <bad-example>
    cd /d "project\\subdir" && dir
    </bad-example>`
}

function profile(name: string, platform: NodeJS.Platform, limits: Limits, defaultTimeoutMs: number) {
  const isPowerShell = PS.has(name)
  const chain = chainGuidance(name)
  if (CMD.has(name)) {
    return {
      intro: `执行给定的 ${shellDisplayName(name)} 命令，可设置 optional timeout，并确保适当处理和安全措施。`,
      workdirSection:
        "默认情况下，所有命令都在当前工作目录运行。如果需要在不同目录运行命令，使用 `workdir` 参数。避免在命令内部切换目录，改用 `workdir`。",
      commandSection: cmdCommandSection(chain, limits, defaultTimeoutMs),
      gitCommands: "git commands",
      gitCommandRestriction: "git commands",
      createPrInstruction: "使用临时 body 文件创建 PR，让 cmd.exe quoting 保持简单。",
      createPrExample: `(\n  echo ## Summary\n  echo - ^<1-3 bullet points^>\n) > pr-body.txt\ngh pr create --title "the pr title" --body-file pr-body.txt`,
      parameterDescription: descriptions.cmd,
    }
  }
  if (isPowerShell) {
    return {
      intro: `执行给定的 ${shellDisplayName(name)} 命令，可设置 optional timeout，并确保适当处理和安全措施。`,
      workdirSection:
        "默认情况下，所有命令都在当前工作目录运行。如果需要在不同目录运行命令，使用 `workdir` 参数。避免在命令内部切换目录，改用 `workdir`。",
      commandSection: powershellCommandSection(
        name,
        chain,
        platform === "win32" ? "\\" : "/",
        limits,
        defaultTimeoutMs,
      ),
      gitCommands: "git commands",
      gitCommandRestriction: "git commands",
      createPrInstruction: "使用 gh pr create 创建 PR，并用 PowerShell here-string 正确传递 body。",
      createPrExample: `gh pr create --title "the pr title" --body @'
## Summary
- <1-3 bullet points>
'@`,
      parameterDescription: descriptions.powershell,
    }
  }
  return {
    intro:
      "在持久 shell session 中执行给定 bash 命令，可设置 optional timeout，并确保适当处理和安全措施。",
    workdirSection:
      "默认情况下，所有命令都在当前工作目录运行。如果需要在不同目录运行命令，使用 `workdir` 参数。避免使用 `cd <directory> && <command>` 模式，改用 `workdir`。",
    commandSection: bashCommandSection(chain, limits, defaultTimeoutMs),
    gitCommands: "bash commands",
    gitCommandRestriction: "git bash commands",
    createPrInstruction:
      "使用以下格式通过 gh pr create 创建 PR。使用 HEREDOC 传递 body，以确保格式正确。",
    createPrExample: `gh pr create --title "the pr title" --body "$(cat <<'EOF'
## Summary
<1-3 bullet points>`,
    parameterDescription: descriptions.bash,
  }
}

export function render(name: string, platform: NodeJS.Platform, limits: Limits, defaultTimeoutMs: number) {
  const selected = profile(name, platform, limits, defaultTimeoutMs)
  return {
    description: renderPrompt(DESCRIPTION, {
      intro: selected.intro,
      os: platform,
      shell: name,
      tmp: Global.Path.tmp,
      workdirSection: selected.workdirSection,
      commandSection: selected.commandSection,
      gitCommands: selected.gitCommands,
      toolName: ShellID.ToolID,
      gitCommandRestriction: selected.gitCommandRestriction,
      createPrInstruction: selected.createPrInstruction,
      createPrExample: selected.createPrExample,
    }),
    parameters: parameterSchema(selected.parameterDescription),
  }
}

export * as ShellPrompt from "./prompt"
