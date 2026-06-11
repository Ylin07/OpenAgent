# OpenAgent

OpenAgent 是一个基于 Bun/TypeScript 的终端 AI 开发工具。项目提供可交互的 TUI、会话管理、模型/Provider 接入、插件与 SDK 能力，并在本仓库中内置了一套面向授权 CTF 场景的 agent、skills、tools 和知识库。

本项目适合两类使用方式：

- 作为本地 AI 编程助手，在项目目录中启动 TUI，让模型读取、分析、修改和验证代码。
- 作为授权 CTF/lab/wargame 训练助手，使用 `.openagent` 中的 CTF 专项配置处理 reverse、pwn、web 等题型。

## 功能特性

- 终端 TUI：在当前项目目录中启动 AI 编程会话。
- 多会话支持：继续最近会话、指定 session 继续、或 fork 历史会话。
- 模型选择：支持通过 `provider/model` 格式指定模型。
- Provider 连接：可在 TUI 中连接模型服务商，也可通过配置文件管理默认模型。
- 插件系统：支持加载本地或外部插件，扩展 tool、TUI slot、provider、agent 等能力。
- SDK/server：提供 `@openagent-ai/sdk` 和 server/http API 相关包，便于二次集成。
- CTF 扩展：内置 `ctf` agent、`ctf-*` skills、CTF 工具封装和本地知识库。
- Monorepo 架构：core、server、plugin、sdk、ui、openagent CLI 分包维护。

## 目录结构

```text
.
|-- .openagent/                 # 本仓库内置的 OpenAgent 配置和 CTF 扩展
|   |-- agent/ctf.md            # CTF 专项 agent
|   |-- skills/                 # CTF triage/pwn/reverse/web skills
|   |-- tool/ctf.ts             # CTF 工具导出入口
|   |-- ctf/                    # CTF 工具实现
|   `-- docs/                   # CTF 本地知识库
|-- packages/
|   |-- openagent/              # CLI/TUI 主程序
|   |-- core/                   # 核心配置、会话、工具、权限、数据库等能力
|   |-- server/                 # server 和 HTTP API 处理逻辑
|   |-- plugin/                 # 插件 API
|   |-- sdk/js/                 # JavaScript SDK
|   |-- llm/                    # LLM 消息/schema 相关模块
|   |-- ui/                     # UI 相关包
|   `-- effect-drizzle-sqlite/  # Effect + Drizzle SQLite 适配
|-- package.json
|-- bun.lock
|-- Makefile
`-- turbo.json
```

## 环境要求

- Bun `1.3.14` 或兼容版本
- Git
- Node.js，用于 Makefile 中的配置部署脚本
- Python 3 和 pip，用于 CTF/pwntools/solver 脚本
- Ruby 和 gem，用于 `one_gadget`
- GNU binutils：`strings`、`readelf`、`objdump`
- Linux/macOS/WSL 推荐
- 如果要构建本地二进制，需要系统具备常见 C/C++ 编译依赖

确认 Bun 是否可用：

```bash
bun --version
```

## 一键安装环境工具

推荐直接运行安装脚本：

```bash
bash scripts/install-env.sh
```

或者通过 Makefile：

```bash
make install-tools
```

脚本会自动识别 `apt-get`、`dnf`、`pacman` 或 `brew`，安装基础开发工具、CTF 工具链、Python/Ruby 包，并执行 `bun install`。

常用参数：

```bash
# 只检查当前缺少哪些工具，不安装
bash scripts/install-env.sh --check-only

# 只安装基础开发环境，不安装 CTF 工具
bash scripts/install-env.sh --base-only

# 安装重型 reverse/solver 依赖，例如 angr/angrop
bash scripts/install-env.sh --heavy

# 只安装系统和语言工具，不执行 bun install
bash scripts/install-env.sh --no-project
```

基础开发工具：

- `bun`：运行 workspace、启动 CLI/TUI、执行测试和构建。
- `git`：版本控制和上传 GitHub。
- `node`：执行 Makefile 中的配置写入脚本。
- `make`、`gcc`、`g++`、`pkg-config`：构建 native 依赖和二进制产物。
- `python3`、`pip`：运行脚本和安装 CTF Python 包。
- `curl`、`jq`、`ripgrep`：下载、JSON 处理和快速搜索。

CTF 工具链：

- `file`、`strings`、`readelf`、`objdump`：二进制基础识别、符号、section 和反汇编。
- `checksec`：检查 ELF 保护，例如 NX、PIE、Canary、RELRO。
- `gdb`：crash offset、heap snapshot、动态 unpack 和调试。
- `patchelf`：切换 interpreter/libc，复现远程 libc 环境。
- `upx`：识别和解包 UPX。
- `pwntools`：exploit 编写、cyclic、ELF/ROP/libc 辅助。
- `ROPgadget`、`ropper`：搜索 ROP gadget、`/bin/sh`、`syscall` 和 ret2csu 候选。
- `one_gadget`：计算 libc one_gadget offset。
- `z3-solver`、`unicorn`、`capstone`、`pycryptodome`：reverse/solver/emulation/crypto 辅助。
- `socat`、`netcat`、`strace`、`ltrace`：本地服务模拟、远程连通和运行时观察。

可选重型工具：

- `angr`、`angrop`：符号执行和自动化 ROP，使用 `--heavy` 安装。
- `radare2`、`rizin`、`binwalk`：脚本会尽量安装；不同发行版包名不稳定，失败时不会中断主流程。

如果脚本安装后仍提示命令不存在，通常是用户级路径没有加入 `PATH`。可临时执行：

```bash
export PATH="$HOME/.bun/bin:$HOME/.local/bin:$PATH"
```

## 安装

克隆项目：

```bash
git clone <你的仓库地址>
cd <仓库目录>
```

安装依赖：

```bash
bun install
```

## 运行

开发模式启动 TUI：

```bash
bun run dev
```

也可以使用 Makefile：

```bash
make dev
```

在指定项目目录启动：

```bash
bun run dev -- /path/to/project
```

指定模型启动：

```bash
bun run dev -- --model provider/model
```

传入初始 prompt：

```bash
bun run dev -- --prompt "请分析这个项目的结构"
```

继续最近一次会话：

```bash
bun run dev -- --continue
```

继续指定 session：

```bash
bun run dev -- --session <session-id>
```

fork 已有会话：

```bash
bun run dev -- --session <session-id> --fork
```

查看 CLI 帮助：

```bash
bun run dev -- --help
```

启动可被外部连接的本地 server：

```bash
bun run dev -- --hostname 127.0.0.1 --port 4096
```

连接已经运行的 OpenAgent server：

```bash
bun run dev -- attach http://127.0.0.1:4096
```

## 构建

构建 openagent 二进制：

```bash
make build
```

运行构建产物：

```bash
make run
```

当前 Makefile 的构建产物路径为：

```text
packages/openagent/dist/openagent-linux-x64/bin/openagent
```

## CTF 扩展用法

仓库中的 `.openagent` 目录已经包含 CTF 相关配置：

- `agent/ctf.md`：CTF 专项主 agent。
- `skills/ctf-triage`：题型分诊。
- `skills/ctf-pwn`：pwn/binary exploitation 工作流。
- `skills/ctf-reverse`：reverse engineering 工作流。
- `skills/ctf-web`：Web CTF 工作流。
- `tool/ctf.ts`：统一导出 CTF 工具。
- `docs/`：pwn/reverse 等本地参考文档。

将本仓库的 CTF 配置部署到全局 OpenAgent 配置目录：

```bash
make deploy
```

默认会复制到：

```text
~/.config/openagent/
```

部署后可在任意授权 CTF 项目目录中启动：

```bash
openagent --agent ctf
```

如果使用开发模式，可以在本仓库内直接指定 CTF agent：

```bash
bun run dev -- --agent ctf
```

清理已部署的全局 CTF 配置：

```bash
make clean
```

注意：CTF 扩展仅用于授权的 CTF、lab、wargame 或 training 目标，不应用于真实第三方系统。

## 常用命令

```bash
# 安装依赖
bun install

# 开发模式启动
bun run dev

# 一键安装开发和 CTF 环境工具
make install-tools

# 测试所有 workspace package
bun run test

# CI 测试
bun run test:ci

# 类型检查
bun run typecheck

# 构建 openagent
make build

# 运行构建产物
make run

# 部署 CTF 扩展
make deploy

# 清理构建缓存和产物
make clean-build
```

## 配置说明

OpenAgent 会读取全局配置和项目配置。默认项目配置目录为：

```text
.openagent/
```

全局配置目录通常为：

```text
~/.config/openagent/
```

本仓库提供的 `.openagent/openagent.jsonc` 示例：

```jsonc
{
  "$schema": "https://openagent.ai/config.json",
  "skills": {
    "paths": [".openagent/skills"]
  },
  "permission": {
    "external_directory": {
      "~/.config/openagent/docs/*": "allow"
    }
  },
  "tool_output": {
    "max_lines": 2500,
    "max_bytes": 80000
  }
}
```

常见配置项：

- `model`：默认模型，例如 `provider/model`。
- `default_agent`：默认主 agent。
- `provider`：自定义或覆盖模型 provider。
- `permission`：工具权限规则。
- `skills`：额外 skill 路径。
- `plugin`：外部插件列表。
- `tool_output`：工具输出截断限制。

## GitHub 下载方式

项目上传到 GitHub 后，别人可以通过以下方式下载：

```bash
git clone https://github.com/<owner>/<repo>.git
```

也可以直接下载 ZIP：

```text
https://github.com/<owner>/<repo>/archive/refs/heads/main.zip
```

把 `<owner>` 和 `<repo>` 替换成你的 GitHub 用户名和仓库名即可。

## 开发说明

这是一个 Bun workspace 项目，根目录 `package.json` 管理所有子包：

```json
{
  "workspaces": {
    "packages": [
      "packages/core",
      "packages/effect-drizzle-sqlite",
      "packages/llm",
      "packages/openagent",
      "packages/plugin",
      "packages/sdk/js",
      "packages/server",
      "packages/ui"
    ]
  }
}
```

新增功能时优先按现有模块边界放置：

- CLI/TUI 行为放在 `packages/openagent`。
- 会话、权限、工具、配置等共享逻辑放在 `packages/core`。
- HTTP/API 处理放在 `packages/server`。
- 插件类型和扩展 API 放在 `packages/plugin`。
- SDK 客户端放在 `packages/sdk/js`。

## License

MIT
