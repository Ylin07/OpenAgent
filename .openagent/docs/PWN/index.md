# PWN 题型索引

PWN 解题的第一步不是直接写 exp，而是先把题目的保护、漏洞入口和最终目标拆开。当前知识库里的内容可以按下面的顺序使用：

1. `file` 判断架构，`checksec` 判断 Canary/NX/PIE/RELRO。
2. 静态分析找危险函数、菜单逻辑、GOT/PLT、后门函数、字符串、系统调用 gadget。
3. 动态调试验证偏移、栈布局、堆布局、泄露值和执行流。
4. 根据保护选择利用链：直接劫持返回地址、注入 shellcode、ROP、ret2libc、格式化字符串任意写、堆链表攻击、FSOP、ORW、内核提权等。

## 快速判断表

| 现象 | 题型 | 解法入口 |
| --- | --- | --- |
| 栈上缓冲区长度不受控，返回时崩溃 | 栈溢出 | [栈溢出原理](./stack-rop.md#栈溢出原理) |
| 程序自带 `system("/bin/sh")` 或 `success()` | ret2text | [ret2text](./stack-rop.md#ret2text) |
| NX 关闭，栈或 bss 是 `rwx` | ret2shellcode | [ret2shellcode](./stack-rop.md#ret2shellcode) |
| NX 开启但有 `int 0x80` / `syscall` 和寄存器 gadget | ret2syscall | [ret2syscall](./stack-rop.md#ret2syscall) |
| 能泄露 libc 函数地址，随后二次触发漏洞 | ret2libc | [ret2libc](./stack-rop.md#ret2libc) |
| 64 位参数 gadget 不全 | ret2csu | [ret2csu](./stack-rop.md#ret2csu) |
| 动态链接解析可被伪造 | ret2dlresolve | [ret2dlresolve](./stack-rop.md#ret2dlresolve) |
| `printf(buf)` 或格式字符串第一个参数可控 | 格式化字符串 | [格式化字符串](./format-string.md) |
| `add/delete/edit/show` 菜单，释放后还能读写 | UAF / double free / heap overflow | [堆利用与 FSOP](./heap-fsop.md) |
| `show` 能打印 free 后的大 chunk | unsorted bin leak | [unsorted bin](./heap-fsop.md#unsorted-bin) |
| 可覆盖 `_IO_list_all` 或 FILE vtable | FSOP | [FSOP](./heap-fsop.md#fsop) |
| seccomp 禁用 shell | ORW | [seccomp 与 ORW](./advanced.md#seccomp--orw) |
| 给了内核模块和 QEMU 启动环境 | kernel pwn | [kernel pwn](./advanced.md#kernel-pwn) |
| 本地成功但远程崩溃 | 环境差异 | [本地 vs 远程](#本地-vs-远程常见差异) |

## 本地 vs 远程常见差异

本地 exploit 成功不等于远程成功。以下是按频率排列的排查清单：

| 现象 | 常见原因 | 解决 |
| --- | --- | --- |
| 远程 `SIGSEGV` 在 `movaps` | 栈未 16-byte 对齐，本地/远程环境变量数量不同 | 加一条 `ret` gadget 调整栈对齐，见 [ret2libc 堆栈对齐](./stack-rop.md#堆栈对齐问题-x86-64-stack-alignment) |
| 远程 `SIGSEGV` 地址偏移固定 | libc 版本不匹配 | 重新 `ctf_libc assume="remote"` 在线匹配远程 libc |
| 远程直接超时/无回应 | remote banner/menu 需要先接收 | 在 payload 前加 `io.recvuntil(b"menu")` 或类似 |
| 远程有输出但内容不对 | `\x00` 截断（`strcpy`/`gets` 停止在 null byte） | 改用无 null byte 的地址、部分覆盖、或换用 ROP 链 |
| 远程出 `EOF` | 连接被重置，payload 导致程序 crash 但没拿到 shell | 检查 offset、alignment、重新用 cyclic pattern 验证 |
| 本地 `patchelf` 后本地闪退 | `patchelf` 用错了 libc 或 interpreter | 用 pwninit / `patchelf --set-interpreter ld.so --replace-needed libc.so.6 ./given_libc.so ./pwn` |

核心原则：
1. 远程给 libc 就一定要用那个 libc 本地测试，不要用系统自带 libc。
2. 所有涉及 `system()` 的 ROP 链，默认加 `ret` gadget 修对齐。
3. 打远程前总是先在本地用 `env -i` 清空环境变量运行一次。

## 常用命令

```sh
file ./pwn
checksec ./pwn
ROPgadget --binary ./pwn --only "pop|ret|syscall|int"
ROPgadget --binary ./pwn --string "/bin/sh"
objdump -d -M intel ./pwn | less
readelf -a ./pwn
```

常用 pwntools 骨架：

```python
from pwn import *

context.binary = elf = ELF("./pwn")
context.log_level = "debug"

io = process(elf.path)
# io = remote("host", port)

payload = b"A" * offset
io.sendline(payload)
io.interactive()
```
