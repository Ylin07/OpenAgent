# 混淆、反调试与脱壳题型解法

## 总体判断

如果一个 RE 题出现下面情况，先不要急着分析业务逻辑，应先处理保护：

- IDA/Ghidra 不能正常反编译。
- 反汇编从中途开始明显错位。
- 程序运行时和静态反汇编不一致。
- 调试时行为改变、退出或崩溃。
- PE 入口不是真实入口，导入表很少或损坏。
- 大量无意义跳转、异常、`int 3`、`ptrace`、TLS 回调。

处理顺序建议：

1. 判断是混淆、反调试还是壳。
2. 尽量恢复可读代码：patch、dump、重建函数、重建 IAT。
3. 再回到常规逆向流程定位核心算法。

## 花指令

花指令是一类不会影响程序原有功能，但会迷惑反汇编器的指令片段。常见技巧是用 `jmp/call/ret` 改变静态分析器看到的执行流，使 IDA 解析出与运行时不一致的代码。

识别特征：

- `main` 无法 F5。
- 出现 `jmp loc+1`、`jmp loc+2`。
- `call` 后面嵌入数据，再通过 `pop/add/push/ret` 改返回地址。
- 指令看起来无意义，但动态运行能正常继续。
- 删除或 nop 某些字节后反汇编恢复正常。

### 例题模式

N1CTF2020 oflo 中，`0x400BB1` 处：

```asm
loc_400BB1:
    jmp short near ptr loc_400BB1+1
```

这会让反汇编器从错误边界解码。处理方式是把第一个字节 patch 为 `0x90`：

```python
import idc
idc.patch_byte(0x400BB1, 0x90)
```

另一个花指令片段：

```asm
call loc_400BBF
db 0E8h, 0EBh, 12h
loc_400BBF:
    pop rax
    add rax, 1
    push rax
    mov rax, rsp
    xchg rax, [rax]
    pop rsp
    mov [rsp], rax
    retn
```

`call` 会把下一条地址压栈，后续代码把返回地址加一再 `ret`，实际执行流从中间字节开始。处理方式是把 `call` 和这段修正返回地址的代码都 patch 为 `nop`。

IDAPython 批量 patch：

```python
import idc

for i in range(0x400BB7, 0x400BBC + 1):
    idc.patch_byte(i, 0x90)

for i in range(0x400BBF, 0x400BD0 + 1):
    idc.patch_byte(i, 0x90)
```

patch 后：

1. 回到函数开头。
2. 按 `u` 取消错误定义。
3. 按 `p` 重新创建函数。
4. 再按 F5 反编译。

### 花指令处理原则

- 先动态确认真实执行流，再 patch。
- patch 时尽量只 nop 掉混淆片段，不动业务逻辑。
- 多处同类花指令可写 IDAPython 批量处理。
- patch 后重新分析函数和控制流图。

## SMC

SMC 即 Self-Modified Code，自修改代码。程序会在运行时修改自身代码，使静态反汇编结果与实际行为不符。修改前的代码段可能不是合法指令，IDA 无法正确识别。

常见特征：

- 调用 `mprotect` 或 `VirtualProtect` 修改代码段权限为可写可执行。
- 对某个函数地址范围做 xor/add/sub 解密。
- 解密后再调用该函数。
- 静态看函数是 `int 3`、乱码或数据。

GWCTF 2019 re3 中的主函数逻辑：

```c
scanf("%39s", s);
if (strlen(s) != 32) {
    puts("Wrong!");
    exit(0);
}
mprotect(&dword_400000, 0xF000, 7);
for (i = 0; i <= 223; ++i)
    *((_BYTE *)sub_402219 + i) ^= 0x99;
sub_40207B(&unk_603170);
sub_402219(s);
```

处理方式：

```python
import idc

for i in range(234):
    idc.patch_byte(0x402219 + i, idc.get_db_byte(0x402219 + i) ^ 0x99)
```

patch 后在 `sub_402219` 开头重新定义函数，即可得到正常伪 C。

### SMC 解题流程

1. 找修改权限 API：`mprotect/VirtualProtect`。
2. 找被修改范围：起始地址、长度、运算方式。
3. 静态 patch 或动态运行到解密后 dump 内存。
4. 重新建函数和反编译。
5. 继续分析真实算法。

两种常用方式：

- 静态 patch：适合异或/加减等简单解密。
- 动态 dump：适合多层解密、运行时 key、复杂解码。

## 控制流平坦化

控制流平坦化是作用于控制流图的混淆技术。它把原函数的基本块关系重新组织，插入一个“主分发器”来控制执行流程。原本自然的分支/循环被状态变量和分发循环替代。

识别特征：

- CFG 像一个大循环，所有基本块回到同一个 dispatcher。
- 有一个状态变量决定下一块执行。
- 大量 `switch(state)` 或间接跳转。
- 每个真实基本块最后只修改状态变量。

解法方向：

1. 找 dispatcher 和状态变量。
2. 动态记录状态转移，恢复真实基本块顺序。
3. 静态分析每个块对状态变量的赋值。
4. 使用符号执行自动求路径。
5. 对 OLLVM 类混淆可用现成去平坦化脚本，但要核对结果。

完整实现需要结合具体混淆结构，但核心方向是：利用符号执行恢复控制流。

## 反调试

反调试是通过检测调试器、断点、异常行为、时间差等方式阻止分析。常见 API/技术：

- Linux：`ptrace(PTRACE_TRACEME)`、读取 `/proc/self/status`、断点检测、时间检测。
- Windows：`IsDebuggerPresent`、`CheckRemoteDebuggerPresent`、`NtQueryInformationProcess`、`NtGlobalFlag`、Heap flags、TLS、SEH、`int 3`。

### ptrace 检测

原理：一个进程只能被一个进程 ptrace。如果程序自己调用：

```c
if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
    printf("DEBUGGING... Bye\n");
    return 1;
}
```

在 gdb 调试下，`ptrace` 返回错误，程序判断被调试。

绕过方法 1：修改返回值。

```gdb
b ptrace
r
finish
set $eax=0
c
```

64 位下返回值寄存器是 `rax`。

绕过方法 2：patch 调用或校验分支。

- nop 掉 `call ptrace`。
- patch `test eax,eax; js fail` 为永远不跳。

绕过方法 3：`LD_PRELOAD` 替换函数。

```c
int ptrace(int i, int j, int k, int l) {
    return 0;
}
```

编译：

```sh
gcc -shared -fPIC ptrace.c -o ptrace.so
LD_PRELOAD=./ptrace.so ./target
```

### 断点检测

gdb 软件断点通过把目标地址字节替换为 `0xcc` 实现。程序可以检测函数入口是否为 `0xcc`：

```c
if ((*(volatile unsigned *)((unsigned)foo) & 0xff) == 0xcc) {
    printf("BREAKPOINT\n");
    exit(1);
}
```

绕过：

- 不在被检测位置下软件断点。
- 使用硬件断点。
- 改用 `ICEBP(0xF1)`。
- patch 检测代码。
- 搜索反汇编中与 `0xcc` 相关的比较。

可用 perl 过滤：

```perl
#!/usr/bin/perl
while(<>) {
    if($_ =~ m/([0-9a-f][4]:\s*[0-9a-f \t]*.*0xcc)/) { print; }
}
```

使用：

```sh
objdump -M intel -d xxx | ./antibp.pl
```

### LD_PRELOAD 加速或替换

`LD_PRELOAD` 会让动态加载器先加载指定共享库，同名函数会优先被调用。静态链接程序不受影响，`ruid != euid` 时也会受限制。

HITB 例题中，程序大量循环调用 `sleep/time/printf`，可以：

1. patch 掉耗时 `printf`。
2. 用 `LD_PRELOAD` 替换 `sleep` 和 `time`。

示例：

```c
static int t = 0x31337;

void sleep(int sec) {
    t += sec;
}

int time() {
    return t;
}
```

编译运行：

```sh
gcc --shared -fPIC time.c -o time.so
LD_PRELOAD=./time.so ./patched.elf
```

## 脱壳

壳是先于原程序运行的一段保护程序。它拿到控制权后完成解压、解密、导入表修复、反调试等工作，最后跳到原程序入口点 OEP。

壳分类：

- 压缩壳：缩小 PE 文件体积，隐藏代码和资源。常见 UPX、ASPack。
- 加密壳/保护壳：防逆向分析，常见 Themida、VMProtect、ASProtect。

壳加载过程：

1. 保存入口参数和寄存器，常见 `pushad/pushfd`。
2. 获取所需 API，导入表中常只剩 `GetProcAddress`、`GetModuleHandle`、`LoadLibrary`。
3. 解密/解压各区块数据。
4. 恢复 IAT 和重定位。
5. 跳回 OEP。

### 单步跟踪法

通过 OllyDbg 的 F8/F7/F4 完整走过自脱壳过程。

要点：

1. 打开程序后 F8 单步向下，尽量实现向下跳转。
2. 遇到大循环，用 F4 跳过。
3. 入口附近的近 call 尽量 F7 进入。
4. 跳转幅度大的 jmp 很可能跳到 OEP。

常见 OEP 前片段：

```asm
popad
jnz short target
push OEP
retn
```

### ESP 定律法

ESP 定律利用壳保存/恢复寄存器时的栈平衡快速找到 OEP。很多壳入口用 `pushad` 保存寄存器，脱壳结束用 `popad` 恢复。对保存后的 ESP 设置硬件断点，运行到断点后，通常离 OEP 很近。

要点：

1. 程序入口执行 `pushad/pushfd`。
2. 执行后记录 ESP。
3. 对 ESP 指向内存设置硬件访问断点。
4. F9 运行到断点。
5. 删除断点，单步到 OEP。

### 一步到达 OEP

适合特征明显的压缩壳。搜索 `popad` 等壳特征指令：

1. `Ctrl+F` 查找 `popad`。
2. `Ctrl+L` 找下一个。
3. 判断该位置是否为解压完毕即将跳 OEP。
4. 下断点运行到该处。

只适用于部分壳，复杂保护壳不稳定。

### 最后一次异常法

某些壳在自解压/自解密过程中触发大量异常。最后一次异常附近可能接近 OEP。

操作流程：

1. 调试选项中取消忽略异常。
2. `Shift+F9` 直到程序运行，记录异常次数 `m`。
3. 重载程序，按 `Shift+F9` 共 `m-1` 次。
4. 查看 SE 句柄地址。
5. 到 SE 处理地址下断，再 `Shift+F9`。
6. 单步跟踪到 OEP。

### 内存镜像法

原理：壳常先访问资源段，再转回代码段。对资源段和代码段设置内存一次性断点，可快速断到 OEP。

流程：

1. 勾选忽略异常。
2. `Alt+M` 打开内存镜像。
3. 找 `.rsrc` 段，下内存断点。
4. 运行到断点。
5. 再对 `.text` 段下断。
6. 继续运行，通常停在 OEP。

### DUMP 与 IAT 重建

找到 OEP 后，需要 dump 程序并修复 IAT。IAT 是 Import Address Table，表项指向导入函数实际地址。

基础流程：

1. 在 OEP 位置用 OllyDump/LoadPE dump。
2. dump 时先取消自动重建输入表。
3. 打开 ImportREC，选择正在调试的原进程。
4. 填 OEP：`OEP_RVA = OEP - ImageBase`。
5. `AutoSearch` 找 IAT。
6. `Get Imports` 检查导入函数有效。
7. `Fix Dump` 修复 dump 文件。

手动找 IAT：

1. 在 OEP 附近右键查找所有模块间调用。
2. 跟随调用地址到数据窗口。
3. 把数据窗口显示为地址/函数名。
4. 向上找 IAT 起始，向下找结束。
5. 记录 RVA 和 size。
6. 在 ImportREC 手动填 `OEP/RVA/SIZE`。

## 总结

混淆、反调试和壳的目标都是让你看不到真实逻辑。处理原则：

- 花指令：恢复正确反汇编边界。
- SMC：拿到运行时真实代码。
- 平坦化：恢复真实控制流。
- 反调试：让程序在调试器下表现正常。
- 脱壳：找到 OEP，dump，修 IAT。

保护处理完后，再回到常规逆向流程分析输入、变换和比较。
