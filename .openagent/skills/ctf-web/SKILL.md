---
name: ctf-web
description: "必须用于授权 CTF Web：HTTP target、本地 Web app、source disclosure、hidden route、form、cookie、auth bypass、upload、SSTI、SQL/NoSQL injection、path traversal、SSRF-style lab、API、JavaScript endpoint。"
---

# CTF WEB

## 强制边界

- 只处理授权 CTF、lab、wargame、training 目标。
- 必须限制在题目授权边界内；除非题目明确给出其他授权 host，否则只允许同源测试。
- 禁止广域扫描、目录爆破、破坏性 payload、持久化、隐藏行为和无关数据读取。
- 每一轮只能测试一个入口和一个 payload family。

## 必须执行顺序

1. 必须调用 `ctf_status`，除非本轮会话已经调用过。
2. 必须确认 base URL 和授权边界。
3. 必须调用 `ctf_web`，`includeCommon=true`；额外 paths 必须保持短列表且同源。
4. 必须用 `ctf_note` 记录 routes、forms、cookies、scripts、comments、headers、异常响应。
5. 必须基于响应差异选择下一步；禁止 payload spraying。

## 表面枚举硬规则

必须优先记录以下证据：

- HTML comments、hidden inputs、form method/action、JS files、API endpoint。
- Cookies、redirects、auth state、debug headers、framework signatures。
- CTF 常见 disclosure：`robots.txt`、`sitemap.xml`、`.git/HEAD`、`source`、`backup`、`www.zip`、`flag.txt`。
- 题目提供的本地源码。

短同源路径检查必须使用 `ctf_web` 的 path list。只有 `ctf_web` 无法表达精确请求时，才允许使用 `ctf_run` 跑短 `curl` 或脚本。

## Payload 选择规则

必须按证据选择 payload：

- 发现 source disclosure 或 backup 时，必须先读源码，再打精确 route 和 parameter。
- auth/login 流程必须比较 valid-looking、invalid、empty、boundary 输入，并记录 cookie/redirect 差异。
- SQL/NoSQL 线索必须先对单一参数做最小 boolean/time/error 差异测试。
- SSTI/template 线索必须先用无害 arithmetic 或 marker payload 验证；禁止直接上文件/命令 primitive。
- Path traversal/LFI 线索必须先对已知无害文件做 normalized traversal 验证，再考虑 flag 路径。
- Upload 线索必须先确认 extension、MIME、存储路径和 parser 行为，再尝试绕过。
- SSRF-style lab 必须限制在题目给出的 internal target 内。

## 记录与完成条件

每个响应差异必须用 `ctf_note` 记录：

- URL/path、method、parameter、payload class；
- status/body/header 差异；
- 当前假设和下一步最小测试。

出现候选 flag 时，必须调用 `ctf_flag`。最终回答必须包含精确请求、关键响应证据和 flag 候选。
