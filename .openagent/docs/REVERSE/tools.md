# REVERSE 工具与自动化

## Z3

Z3 是 SMT solver，用于检查逻辑表达式的可满足性，并找到一组可行解。逆向题中遇到复杂约束时，可以用 Z3 辅助求解。

适用特征：

- 输入每个字符有很多线性/位运算约束。
- 代码里是大量 `if (expr != const) fail`。
- 密码长度固定，字符范围可约束。
- 手写爆破空间太大，但每个条件能翻译成表达式。

安装：

```sh
pip3 install z3-solver
```

### 基本变量

```python
import z3

x = z3.Int("x")
y = z3.Real("y")
z = z3.BitVec("z", 32)
p = z3.Bool("p")
```

逆向中最常用 `BitVec`，因为 C 语言里的 `char/int/uint32_t` 都有固定位宽和溢出行为。

### 求解器

```python
s = z3.Solver()
s.add(x * 5 == 10)
s.add(y / 2 == x)

if s.check() == z3.sat:
    print(s.model())
```

返回：

- `sat`：约束可满足。
- `unsat`：约束不可满足。

### 字符约束骨架

```python
from z3 import *

n = 32
flag = [BitVec(f"flag_{i}", 8) for i in range(n)]
s = Solver()

for c in flag:
    s.add(c >= 0x20, c <= 0x7e)

s.add(flag[0] == ord("f"))
s.add(flag[1] == ord("l"))
s.add(flag[2] == ord("a"))
s.add(flag[3] == ord("g"))
s.add(flag[4] == ord("{"))
s.add(flag[-1] == ord("}"))

# 从反编译结果翻译约束
s.add((flag[5] ^ flag[6]) == 0x12)
s.add((flag[7] + flag[8]) & 0xff == 0xa3)

if s.check() == sat:
    m = s.model()
    ans = bytes([m[c].as_long() for c in flag])
    print(ans)
```

注意：

- `BitVec(8)` 运算会自动按 8 位截断。
- 如果反编译中是 `int`，可能需要 `BitVec(32)`。
- C 中有符号/无符号比较不同，Z3 里要区分。
- 字节转更宽类型时要用 `ZeroExt` 或 `SignExt`。

### 逆向翻译技巧

常见 C 表达式：

```c
((a << 3) ^ b) + c == 0x66
```

Z3：

```python
s.add((((a << 3) ^ b) + c) & 0xff == 0x66)
```

如果 `a/b/c` 是 8 位 `BitVec`，可以不用 `& 0xff`，但显式写出更贴近 C 的无符号 char 行为。

如果约束是数组重排：

```python
idx = [3, 1, 4, 0, 2]
s.add(flag[idx[0]] + flag[idx[1]] == 0x91)
```

## angr

angr 是 Python 编写的跨平台二进制混合执行引擎。它能模拟程序路径，并把输入符号化，自动寻找到达成功分支的输入。

适用特征：

- 成功/失败地址清楚。
- 程序逻辑主要是纯计算。
- 输入来自 stdin 或 argv。
- 手动分析路径太多，但没有复杂反调试、系统交互或加密库调用。

安装：

```sh
pip3 install angr
pip3 install angr-management
pip3 install angrop
```

### Project

```python
import angr

proj = angr.Project("./test")
print(proj.arch)
print(hex(proj.entry))
print(proj.filename)
```

常用信息：

- `proj.arch.bits`：位数。
- `proj.arch.memory_endness`：大小端。
- `proj.entry`：入口地址。

### state

angr 用 `SimState` 表示程序状态：

```python
state = proj.factory.entry_state()
state = proj.factory.blank_state(addr=0x401000)
```

常用接口：

- `state.regs`：寄存器。
- `state.memory.load(addr, size)`：读内存。
- `state.memory.store(addr, data)`：写内存。
- `state.posix.dumps(fd)`：读取 stdout/stderr/stdin 流。
- `state.solver`：求解符号变量。

### simulation_manager

```python
simgr = proj.factory.simgr(state)
simgr.explore(find=0x401234, avoid=0x401111)
```

`find` 可以是地址，也可以是函数：

```python
def is_success(state):
    return b"Good" in state.posix.dumps(1)

def should_abort(state):
    return b"Wrong" in state.posix.dumps(1)

simgr.explore(find=is_success, avoid=should_abort)
```

### stdin 符号化骨架

```python
import angr
import claripy

proj = angr.Project("./re", auto_load_libs=False)

n = 32
flag = claripy.BVS("flag", n * 8)
state = proj.factory.full_init_state(stdin=flag)

for i in range(n):
    c = flag.get_byte(i)
    state.solver.add(c >= 0x20)
    state.solver.add(c <= 0x7e)

simgr = proj.factory.simgr(state)
simgr.explore(find=0x4012ab, avoid=0x401300)

if simgr.found:
    found = simgr.found[0]
    print(found.solver.eval(flag, cast_to=bytes))
```

### 输出判断骨架

```python
def success(state):
    return b"Correct" in state.posix.dumps(1)

def fail(state):
    return b"Wrong" in state.posix.dumps(1)

simgr.explore(find=success, avoid=fail)
```

### 使用注意

- `auto_load_libs=False` 可避免模拟 libc 导致路径爆炸。
- 遇到 `strcmp`、`memcmp` 等库函数，angr 通常能处理，但复杂输入函数可能要 hook。
- 路径爆炸时增加 `avoid`，或从关键函数 `blank_state` 开始。
- 如果程序有反调试、SMC、加壳，先处理保护再 angr。

## Unicorn

Unicorn 是轻量级、多平台、多架构 CPU 模拟器，基于 QEMU。它适合单独模拟一段机器码或函数，而不是完整系统。

适用场景：

- 调用恶意软件或题目中某个函数，但不想运行完整程序。
- 模拟混淆代码。
- 验证一段汇编指令含义。
- 对某段算法做批量输入输出测试。

特点：

- 支持 Arm、Arm64、Mips、Sparc、x86/x86_64 等。
- API 简洁。
- 需要手动映射内存、写入代码和数据。
- 不支持系统调用，遇到 syscall/API 要 hook 或跳过。

安装：

```sh
pip install unicorn
```

### x86 32 位示例

下面示例模拟 `INC ecx; DEC edx`：

```python
from unicorn import *
from unicorn.x86_const import *

X86_CODE32 = b"\x41\x4a"
ADDRESS = 0x1000000

mu = Uc(UC_ARCH_X86, UC_MODE_32)
mu.mem_map(ADDRESS, 2 * 1024 * 1024)
mu.mem_write(ADDRESS, X86_CODE32)

mu.reg_write(UC_X86_REG_ECX, 0x1234)
mu.reg_write(UC_X86_REG_EDX, 0x7890)

mu.emu_start(ADDRESS, ADDRESS + len(X86_CODE32))

print(hex(mu.reg_read(UC_X86_REG_ECX)))
print(hex(mu.reg_read(UC_X86_REG_EDX)))
```

输出中 ECX 加一、EDX 减一。

### 模拟函数骨架

```python
from unicorn import *
from unicorn.x86_const import *

BASE = 0x400000
STACK = 0x700000

code = open("func.bin", "rb").read()

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(BASE, 0x10000)
mu.mem_write(BASE, code)

mu.mem_map(STACK, 0x10000)
mu.reg_write(UC_X86_REG_RSP, STACK + 0x8000)

# 参数
mu.reg_write(UC_X86_REG_RDI, 0x1234)
mu.reg_write(UC_X86_REG_RSI, 0x5678)

mu.emu_start(BASE, BASE + len(code))

print(hex(mu.reg_read(UC_X86_REG_RAX)))
```

如果函数会访问全局表，要把对应表也 `mem_map` 到正确地址；如果遇到外部调用，可以用 hook 拦截。

## LD_PRELOAD

`LD_PRELOAD` 是 Linux 动态加载器的预装载机制。指定的共享库会先于 C 运行库加载，同名函数优先被调用。因此可以用它替换目标程序调用的库函数。

适用场景：

- 绕过 `ptrace`。
- 替换 `sleep/time/rand` 加速。
- 拦截 `strcmp/memcmp` 打印参数。
- Hook 加密函数观察输入输出。

示例：绕过 `ptrace`。

```c
int ptrace(int request, int pid, void *addr, void *data) {
    return 0;
}
```

编译运行：

```sh
gcc -shared -fPIC hook.c -o hook.so
LD_PRELOAD=./hook.so ./target
```

示例：打印 `strcmp` 参数。

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

int strcmp(const char *a, const char *b) {
    static int (*real_strcmp)(const char *, const char *) = NULL;
    if (!real_strcmp) {
        real_strcmp = dlsym(RTLD_NEXT, "strcmp");
    }
    printf("[strcmp] %s | %s\n", a, b);
    return real_strcmp(a, b);
}
```

注意：

- 静态链接程序不受 `LD_PRELOAD` 影响。
- setuid 等权限场景会限制预装载。
- 函数签名必须匹配，否则可能崩溃。

## IDA / Ghidra 基本配合

常规工具流：

1. IDA/Ghidra 做静态结构还原。
2. xrefs 找关键点。
3. 动态调试验证。
4. Python/IDAPython 提取数组、patch、重命名。
5. Z3/angr/Unicorn 自动求解。

IDAPython 常用片段：

```python
import idc

data = []
for i in range(32):
    data.append(idc.get_wide_byte(0x6030A0 + i))
print(data)
```

patch：

```python
for i in range(start, end):
    idc.patch_byte(i, 0x90)
```

提取 dword：

```python
arr = [idc.get_wide_dword(addr + 4 * i) for i in range(n)]
```

## 工具选择总结

| 场景 | 工具 |
| --- | --- |
| 找关键函数、看伪 C | IDA / Ghidra |
| 调试验证寄存器和内存 | GDB / xdbg / OllyDbg |
| 大量约束求输入 | Z3 |
| 自动路径探索 | angr |
| 模拟一段机器码 | Unicorn |
| 替换动态库函数 | LD_PRELOAD |
| 批量 patch / 提取数据 | IDAPython |

工具只能减少重复劳动。真正要先做的是把题目约束抽象清楚：输入在哪里、变换是什么、成功条件在哪里。
