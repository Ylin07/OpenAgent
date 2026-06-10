# CTF PWN / REVERSE 题型知识索引

本目录用于把当前知识库中的 PWN 与 REVERSE 内容按题型重新整理。用法是先看题目给出的特征，再从索引跳到对应专题解法。专题文档尽量沿用 `122-PWN-1.md`、`123-PWN-2.md` 的写法：先写题型原理，再写识别条件、分析步骤、利用/求解流程、脚本骨架和注意点。

## 使用方法

1. 先判断题目类别：二进制远程服务、菜单堆题、格式化字符串、Windows/Linux/Android 逆向、VM/壳/反调试等。
2. 再看保护或混淆：`checksec`、`file`、字符串、导入表、控制流图、是否有 `printf(user_input)`、是否有 `add/delete/edit/show` 菜单、是否存在 `GetDlgItemTextA`、`ptrace`、`mprotect`、`int 3` 等。
3. 根据下面索引进入具体解法。专题正文已经直接整理可用信息，不依赖外部资料链接。

## PWN 特征索引

| 题型特征 | 优先跳转 | 关键词 |
| --- | --- | --- |
| `gets/read/scanf/strcpy` 写入栈，崩溃后能控制返回地址 | [栈溢出与 ROP](./PWN/stack-rop.md) | 栈溢出、offset、ret2text、ret2shellcode |
| NX 开启，程序中能找到 `/bin/sh`、`int 0x80`、`syscall` 或足够 gadget | [栈溢出与 ROP](./PWN/stack-rop.md#ret2syscall) | ret2syscall、ROPgadget、execve |
| 有动态链接函数，能泄露 GOT，之后二次溢出 | [栈溢出与 ROP](./PWN/stack-rop.md#ret2libc) | ret2libc、puts@got、libc base |
| 64 位缺少 `pop rdi/rsi/rdx`，但存在 `__libc_csu_init` | [栈溢出与 ROP](./PWN/stack-rop.md#ret2csu) | ret2csu、csu_front、csu_end |
| 只能触发动态解析，缺少 libc 地址或想伪造解析 | [栈溢出与 ROP](./PWN/stack-rop.md#ret2dlresolve) | ret2dlresolve、`.rel.plt`、`.dynsym`、`.dynstr` |
| 保护里有 Canary，需要先泄露或爆破 | [栈溢出与 ROP](./PWN/stack-rop.md#canary) | Canary、`%p`、fork brute force、`__stack_chk_fail` |
| 存在 `printf(buf)`、`fprintf(user)`、`sprintf(user)` 等格式串可控 | [格式化字符串](./PWN/format-string.md) | `%p`、`%s`、`%n`、GOT leak、任意写 |
| 题目有 `add/edit/delete/show` 菜单，能 UAF、double free、越界改 chunk | [堆利用与 FSOP](./PWN/heap-fsop.md) | tcache、fastbin、unsorted bin、unlink、off-by-one |
| 能泄露 unsorted bin 的 `fd/bk` 指针 | [堆利用与 FSOP](./PWN/heap-fsop.md#unsorted-bin) | main_arena、libc base、unsorted bin leak |
| 能控制 `_IO_FILE`、`_IO_list_all` 或触发 `exit/abort` | [堆利用与 FSOP](./PWN/heap-fsop.md#fsop) | FSOP、fake FILE、vtable、`_IO_overflow` |
| seccomp 禁用 `execve`，目标是读 flag | [高级 PWN 场景](./PWN/advanced.md#seccomp--orw) | ORW、open/read/write、setcontext |
| 题目给内核模块、`run.sh`、`bzImage`、`rootfs.cpio` | [高级 PWN 场景](./PWN/advanced.md#kernel-pwn) | kernel pwn、commit_creds、KPTI、SMEP/SMAP |
| QEMU/设备模拟/虚拟化逃逸 | [高级 PWN 场景](./PWN/advanced.md#qemu--虚拟化逃逸) | MMIO、PMIO、OOB、QEMU monitor |

## REVERSE 特征索引

| 题型特征 | 优先跳转 | 关键词 |
| --- | --- | --- |
| 普通 Linux/Windows 二进制，输入后比对 flag | [常规逆向流程](./REVERSE/basic-workflow.md) | strings、IDA、交叉引用、动态调试 |
| 常量表或 magic number 明显，像 Base64/TEA/RC4/MD5/AES | [算法、迷宫与 VM](./REVERSE/algorithm-maze-vm.md#编码与加密识别) | `0x9e3779b9`、S 盒、Base64 表 |
| 地图字符串、`w/s/a/d`、`L/R/U/D`、坐标变量 | [算法、迷宫与 VM](./REVERSE/algorithm-maze-vm.md#迷宫题) | 迷宫、地图还原、BFS/DFS |
| 大量 opcode 分发，`pc/sp/register`，解释器循环 | [算法、迷宫与 VM](./REVERSE/algorithm-maze-vm.md#虚拟机题) | VM、取指-译码-执行、opcode |
| IDA 不能 F5，跳到指令中间、`jmp loc+1`、无意义 call/ret | [混淆、反调试与脱壳](./REVERSE/obfuscation-anti-debug-unpack.md#花指令) | 花指令、patch、重新建函数 |
| 运行时 `mprotect` 改代码段，代码异或/解密后再调用 | [混淆、反调试与脱壳](./REVERSE/obfuscation-anti-debug-unpack.md#smc) | SMC、dump、IDAPython patch |
| 控制流图呈主分发器结构，大量状态变量跳转 | [混淆、反调试与脱壳](./REVERSE/obfuscation-anti-debug-unpack.md#控制流平坦化) | OLLVM、dispatcher、符号执行 |
| `ptrace`、`IsDebuggerPresent`、`int 3`、TLS、异常链 | [混淆、反调试与脱壳](./REVERSE/obfuscation-anti-debug-unpack.md#反调试) | 反调试、LD_PRELOAD、改返回值 |
| PE 入口异常、`pushad/popad`、OEP、IAT 损坏 | [混淆、反调试与脱壳](./REVERSE/obfuscation-anti-debug-unpack.md#脱壳) | ESP 定律、单步跟踪、ImportREC |
| 约束很多，手算困难 | [工具与自动化](./REVERSE/tools.md#z3) | Z3、SMT、BitVec |
| 路径搜索、找 Good/avoid Bad 自动化求输入 | [工具与自动化](./REVERSE/tools.md#angr) | angr、symbolic execution |
| 想单独模拟一段函数/混淆代码，不想跑完整程序 | [工具与自动化](./REVERSE/tools.md#unicorn) | Unicorn、mem_map、emu_start |

## 文件结构

- [PWN 索引](./PWN/index.md)
- [PWN 栈溢出与 ROP](./PWN/stack-rop.md)
- [PWN 格式化字符串](./PWN/format-string.md)
- [PWN 堆利用与 FSOP](./PWN/heap-fsop.md)
- [PWN 高级场景](./PWN/advanced.md)
- [REVERSE 索引](./REVERSE/index.md)
- [REVERSE 常规流程](./REVERSE/basic-workflow.md)
- [REVERSE 算法、迷宫与 VM](./REVERSE/algorithm-maze-vm.md)
- [REVERSE 混淆、反调试与脱壳](./REVERSE/obfuscation-anti-debug-unpack.md)
- [REVERSE 工具与自动化](./REVERSE/tools.md)
