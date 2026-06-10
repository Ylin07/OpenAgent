# 常规逆向流程

## 题型特征

常规 RE 题通常是一个 Linux/Windows/Android 程序，运行后要求输入 key、serial、flag 或 password。程序内部会对输入做变换，再与常量或计算结果比较。

常见外观：

```text
Input your flag:
Wrong!
Correct!
Good job!
```

这类题的主线是：定位输入、定位变换、定位比较、逆运算或脚本求解。

## 基础流程

常规逆向流程：

1. 使用 `strings/file/binwalk/IDA` 等静态分析工具收集信息，并根据静态信息搜索。
2. 研究程序保护方法，如代码混淆、保护壳、反调试，并设法破除或绕过。
3. 反汇编目标软件，快速定位关键代码。
4. 结合动态调试，验证初期猜想，在分析中理清程序功能。
5. 针对程序功能写脚本，求解 flag。

建议实际操作顺序：

```sh
file ./re
strings -a ./re | less
checksec ./re
readelf -h ./re
readelf -s ./re | less
objdump -d -M intel ./re | less
```

然后用 IDA/Ghidra：

- 看 `main`、`start`、初始化函数。
- 看导入函数：`scanf/read/fgets/GetDlgItemTextA`、`strcmp/memcmp/strncmp`、`MessageBoxA/puts/printf`。
- 看字符串窗口，找 `Wrong`、`Correct`、`flag`、`key` 等提示。
- 对提示字符串做 XREF，回到判断逻辑。

## 定位关键代码

### 控制流

控制流可以参考 IDA 生成的 CFG。沿着分支、循环和函数调用，逐块阅读反汇编或伪 C。常规题通常有：

- 输入长度判断。
- 循环处理每个字符。
- 最终 `memcmp/strcmp` 或逐字节比较。
- 成功/失败分支。

如果分支很多，优先找“成功输出”的交叉引用，从成功分支倒推判断条件。

### 数据和代码交叉引用

最常用方式是字符串 XREF：

1. `Shift+F12` 打开字符串窗口。
2. 找 `Wrong`、`Correct`、`Good job`、`flag`、`KEY`。
3. 按 `x` 看交叉引用。
4. 跳到引用位置，向上回溯输入校验逻辑。

代码交叉引用也很重要。例如图形界面程序获取用户输入常用 Windows API：

```c
GetDlgItemTextA(hDlg, id, buffer, max_len);
```

找到该 API 的 XREF，通常就能定位到按钮回调和关键处理函数。

### 输入函数和比较函数

常见输入：

- Linux：`read`、`scanf`、`fgets`、`gets`、`cin`。
- Windows：`ReadFile`、`scanf`、`gets`、`GetDlgItemTextA`。

常见比较：

- `strcmp`
- `strncmp`
- `memcmp`
- 手写循环比较
- hash/encrypt 后比较常量数组

如果没有明显比较函数，检查：

- 失败分支附近的 `cmp/jz/jnz`。
- 被反编译器还原成 `if (v == const)` 的语句。
- 循环里是否累积 `flag_ok` 或 `result`。

## 逆向分析技巧

下面这些思路适合常规题：

- 编码风格：熟悉常见模式能更快识别函数模块。
- 集中原则：功能相关代码和数据常写在一起，关键代码附近通常还有相关数组、表、函数。
- 代码复用：可用字符串、常量、代码风格去 GitHub 搜索，恢复符号或算法。
- 七分逆向三分猜：看不清函数逻辑时，根据输入输出、常量、调用关系猜功能，再动态验证。
- 区分代码：不要长时间分析库函数、编译器生成代码，要识别出题人自己的逻辑。
- 耐心：复杂程序需要持续把小函数命名、还原结构，逐步降低复杂度。

## 动态分析

动态分析的目的是验证静态猜想，观察寄存器、内存、程序输出和分支走向。

常见断点：

- 输入函数返回后。
- `strcmp/memcmp` 调用前。
- 成功/失败字符串引用位置。
- 最终 `jz/jnz` 判断处。
- 可疑解密函数返回后。

GDB 示例：

```gdb
b *main
b strcmp
b memcmp
r
x/s $rdi
x/s $rsi
ni
set $eax=0
```

Windows x64dbg/OllyDbg 常用：

- 在字符串 XREF 处下断。
- 在 `GetDlgItemTextA`、`MessageBoxA`、`strcmp` 下断。
- 看栈和寄存器里的输入、密文、比较数组。
- 必要时修改 ZF 或 patch 条件跳转验证成功路径。

## 算法和数据结构识别

常见算法：

- TEA/XTEA/XXTEA
- RC4
- AES/DES
- MD5/SHA1/SHA256
- CRC
- Base64/自定义 base64
- 大数运算
- 最短路、图搜索、树、哈希表

识别方式：

- magic number，例如 TEA 的 `0x9e3779b9`。
- 大表，例如 AES S-box、Base64 字符表。
- 循环次数，例如 TEA 32 轮、AES 10/12/14 轮。
- 位运算结构，例如移位、异或、加法混合。
- 数据结构访问模式，例如邻接表、矩阵、队列、栈。

## 写求解脚本

常规题最终尽量写脚本，而不是手工 patch 过关。常见脚本类型：

- 逆运算脚本：把加密流程反过来。
- 暴力脚本：字符集小、长度短时枚举。
- Z3 脚本：约束多但表达清晰。
- angr 脚本：路径条件复杂但成功/失败地址明显。
- 模拟执行脚本：把汇编/字节码翻译成 Python。

脚本骨架：

```python
target = [...]

def decrypt(data):
    out = []
    for i, x in enumerate(data):
        out.append((x ^ i) & 0xff)
    return bytes(out)

print(decrypt(target))
```

## 非常规逆向

非常规逆向题可以是任意架构、任意格式：

- lua/python/java/lua-jit/haskell/applescript/js/solidity/webassembly
- firmware/raw bin
- chip8/avr/clemency/risc-v

通用流程：

1. 阅读文档。快速学习平台/语言的官方文档。
2. 找官方工具。官方工具通常最适合解析和调试。
3. 找教程。前人对该平台的逆向经验可以快速补足背景。
4. 找文件解析工具、反汇编器、调试器、反编译器。

搜索关键词建议：

```text
file format parser
disassembler
debugger
decompiler
bytecode opcode
VM instruction set
```

## 常规题总结模板

拿到一个 RE 题后可以按这个 checklist：

1. `file/strings/checksec` 做第一轮判断。
2. 用 IDA/Ghidra 找 `main` 和导入函数。
3. 从成功/失败字符串 XREF 定位关键判断。
4. 重命名输入、长度、状态变量、比较数组。
5. 把核心变换翻译成 Python。
6. 如果有混淆/反调试/壳，先处理保护。
7. 如果约束太多，用 Z3/angr。
8. 最终脚本输出 flag，必要时回程序验证。
