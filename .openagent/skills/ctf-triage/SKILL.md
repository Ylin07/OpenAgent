---
name: ctf-triage
description: "必须用于授权 CTF 初始分诊：题型不明确、混合题型或刚开始时，先分类为 reverse/pwn/web/mixed，再路由到 ctf-pwn、ctf-reverse、ctf-web，并按需读取 .openagent/docs 索引。"
---

# CTF 初始分诊

## 强制边界

- 只处理授权 CTF、lab、wargame、training 目标。
- 授权或 CTF 范围不明确时，必须先向用户确认；确认前禁止执行网络探测和 exploit-adjacent 操作。
- 本 skill 只负责分诊和路由。分类明确后，必须加载对应领域 skill，禁止在本 skill 内继续深挖。

## 必须执行顺序

1. 必须先调用 `ctf_status`，除非本轮会话已经调用过。
2. 必须先调用 `ctf_doc domain="general" topic="index"`，读取总索引并写入 `.ctf/state.json`。
3. 必须列清输入形态：本地文件/目录、binary、archive、URL、host/port、Docker/QEMU 文件、源码或纯文本描述。
4. 必须基于证据选择一个首个 triage 工具：
   - 本地未知文件/目录：调用 `ctf_reverse`，`deep=false`。
   - ELF pwn、远程二进制服务、crash、libc、ROP、heap 提示：调用 `ctf_pwn`，`deep=false`。
   - 授权 URL 或本地 Web 服务：调用 `ctf_web`，`includeCommon=true`。
   - 壳、高熵、OEP、anti-debug 提示：调用 `ctf_unpack`，`action="identify"`。
5. 必须用 `ctf_note` 记录分类、证据和下一步。
6. 必须加载对应领域 skill 后继续：`ctf-pwn`、`ctf-reverse` 或 `ctf-web`。

## 强制路由规则

- 出现 ELF service、crash、`checksec`、`libc`、`GOT/PLT`、`ROP`、`canary`、`heap`、`malloc/free`、format string、seccomp、kernel/QEMU 时，必须加载 `ctf-pwn`。
- 出现 checker binary、bytecode、archive、APK/PE/ELF 逆向、encoding/encryption、maze、VM、anti-debug、obfuscation、unpacking 时，必须加载 `ctf-reverse`。
- 出现 HTTP URL、forms、cookies、routes、source disclosure、upload、template、SQL/NoSQL、path traversal、SSRF-style lab 时，必须加载 `ctf-web`。
- 混合题必须只保留一个主假设和一个备选假设。必须先执行主假设对应 skill；只有新证据推翻主假设时才能切换。

## Docs 读取规则

- 必须用 `ctf_doc` 读取 docs，禁止用普通 Read 代替。
- 总索引：`ctf_doc domain="general" topic="index"`。
- PWN 索引：`ctf_doc domain="pwn" topic="index"`。
- REVERSE 索引：`ctf_doc domain="reverse" topic="index"`。
- `printf(buf)`、`%p/%n` 证据必须调用 `ctf_doc domain="pwn" topic="format-string"`。
- VM dispatcher、opcode、`pc/sp/register` 证据必须调用 `ctf_doc domain="reverse" topic="algorithm-maze-vm"`。

## 记录要求

每次路由前必须记录：

- 目标路径、URL 或 host/port。
- 工具输出摘要：架构、保护、字符串、路由、导入、异常行为。
- 当前分类和证据。
- 下一步最小动作。

出现候选 flag 时，必须调用 `ctf_flag`。
