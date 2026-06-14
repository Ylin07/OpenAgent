---
name: ctf-pwn
description: "必须用于授权 CTF pwn 和 binary exploitation：ELF service、stack overflow、ROP、ret2libc、ret2csu、ret2dlresolve、format string、heap、FSOP、seccomp ORW、kernel/QEMU、crash offset、libc leak、pwntools exploit。"
---

# CTF PWN

## 强制边界

- 只处理授权 CTF、lab、wargame、training 目标。
- 必须先验证 primitive，再写 exploit；禁止凭猜测直接拼最终 payload。
- 本地 exploit 未稳定前，禁止反复打授权远程服务。
- 每一轮只能推进一个主利用假设。

## 必须执行顺序

1. 必须调用 `ctf_status`，除非本轮会话已经调用过。
2. pwn 子类型不明确时，必须先调用 `ctf_doc domain="pwn" topic="index"`。
3. 必须调用 `ctf_pwn`，`deep=false`，收集 architecture、`checksec`、symbols、imports、strings、可选 remote banner。
4. 必须读取 `ctf_pwn` 输出中的 `Required docs`，逐项调用 `ctf_doc`。未完成这些 `ctf_doc` 前禁止调用 `ctf_rop`、`ctf_libc`、`ctf_heap` 或写 exploit。
5. 必须用 `ctf_note` 记录当前 primitive 假设和证据。
6. 必须按“事实 -> primitive -> leak/控制流 -> exploit -> 本地验证 -> 授权远程验证”的顺序推进。

## 专题文档强制路由（一定要进行这一步!!!）

必须只通过 `ctf_doc` 读取和证据匹配的专题，一定要遵循以下规则：

- Stack overflow、ROP、ret2text、ret2shellcode、ret2syscall、ret2libc、ret2csu、ret2dlresolve、SROP、Canary：调用 `ctf_doc domain="pwn" topic="stack-rop"`。
- Format string leak 或 `%n` 任意写：调用 `ctf_doc domain="pwn" topic="format-string"`。
- 菜单堆、UAF、double free、tcache、fastbin、unsorted bin、unlink、off-by-one、FSOP：调用 `ctf_doc domain="pwn" topic="heap-fsop"`。
- seccomp ORW、kernel pwn、race、QEMU、browser/JS engine：调用 `ctf_doc domain="pwn" topic="advanced"`。

## 工具调用协议

- Baseline 必须使用 `ctf_pwn`。
- 需要危险调用上下文时，必须重新调用 `ctf_pwn` 且 `deep=true`。
- 需要 crash offset 时，必须调用 `ctf_crash`，并显式使用已验证的投递方式：`stdin` 或 `argv`。菜单题必须传入 prefix/suffix。
- 需要 gadget 时，必须调用 `ctf_rop`；题目给 libc 时必须同时传入 `libc`。
- 需要 libc base、`system`、`/bin/sh`、hook 或 one_gadget 地址时，必须调用 `ctf_libc`，并写明 provided/local/remote 假设。
- 需要观察 heap 状态时，必须在有意义的断点或交互阶段调用 `ctf_heap` 的 snapshot/diff/check。
- 写 exploit 时，必须先用 `ctf_pwntools action="template"` 生成模板，再编辑 artifact，再用 `ctf_pwntools action="run"` 运行。
- 只有专用工具无法表达该检查时，才允许使用 `ctf_run` 执行短命令。

## 利用链硬规则

- Canary 开启时，必须先找 leak 或 fork brute force 路径；禁止假设可直接覆盖。
- PIE 开启时，必须先获得 code pointer 或选择非 PIE 路径；禁止硬编码 PIE 内地址。
- NX 开启时，必须使用 ROP/ret2libc/ORW 等代码复用路径；禁止把 shellcode 当默认方案。
- Full RELRO 开启时，禁止把 GOT overwrite 作为主路径。
- ret2libc 必须先证明 leak 解析和 libc base 计算正确，再构造第二阶段。
- heap 题必须先确定 glibc/allocator 版本、chunk size、操作序列和 corruption primitive，再选择 tcache/bin/house/FSOP 路径。
- seccomp 题必须先确认允许 syscall；`execve` 被禁时必须走 ORW 或题目允许的等价读 flag 链。
- 任何涉及调用 libc 函数（`system`、`execve`、`one_gadget`）的 ROP 链，必须检查并保证 x86-64 下栈 16-byte 对齐。`system()` 内部的 `movaps` 指令要求 `rsp % 16 == 0`。若不对齐，在 ROP 链最前面插入一条 `ret` gadget 调整栈指针。
- 本地 exploit 测试成功不能直接认为远程也会成功。本地和远程必须视为不同环境。

## 工具信任规则

- CTF 工具返回的结果是权威的。不要用 `bash` 或手工命令重复验证 CTF 工具已经返回的结果。
- `ctf_pwn` 返回的 checksec、symbols、imports、strings 是完整的第一手数据，直接使用无需二次确认。
- `ctf_crash` 返回的 offset 是已通过 cyclic pattern 验证的结果，直接用于 payload 构造。
- `ctf_libc` 返回的地址和 one_gadget 已经过计算和验证，直接使用。
- `ctf_rop` 返回的 gadget 列表已经过滤和验证，直接从中选择。
- 如果一个工具结果看起来可疑，优先换用另一个专用 CTF 工具交叉验证，不要用原始命令重复。

## 本地 vs 远程环境

- 本地环境和远程环境本质上是两台不同机器。差异来源：
  - libc 版本不同 → `system`、`__free_hook`、`one_gadget` 偏移不同
  - 栈布局不同 → 环境变量数量/长度不同，`argv` 不同，导致栈地址偏移
  - ASLR 强度不同 → 32 位远程可能几乎无随机化，但本地内核可能做满
  - 容器环境 → `seccomp` 规则不同、`/proc` 不可用、文件系统不同
- 远程题目给了 libc 文件时，必须用 `ctf_libc assume="provided"` 并传入该 libc，且用 `patchelf --set-interpreter` + `LD_PRELOAD` 在本地加载远程 libc 测试。
- 远程没给 libc 时，用 `ctf_libc assume="remote"` 在线匹配 libc 版本。至少泄露 2 个函数地址以确认匹配正确。
- 本地成功、远程失败时，排查清单（按顺序）：
  1. libc 版本是否匹配？（重新 `ctf_libc assume="remote"`）
  2. 栈对齐是否正确？（加 `ret` gadget）
  3. 是否有 `\x00` 截断导致 payload 不完整？（检查 `strcpy`/`gets` 等）
  4. 远程是否需要在发送 payload 前接收 banner/menu？

## 记录与完成条件

每个关键事实必须用 `ctf_note` 记录：

- primitive、offset、leak 来源、computed base、gadget chain、heap layout；
- 产生该事实的工具或命令；
- 下一步最小验证动作。

出现候选 flag 时，必须调用 `ctf_flag`。最终回答必须包含已验证路径、关键 offset/address、运行 exploit 的命令和仍不确定的点。
