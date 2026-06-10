# 算法、迷宫与 VM 题型解法

## 编码与加密识别

CTF 逆向中经常出现 Base64、TEA、AES、RC4、MD5 等编码或加密算法。快速识别算法能显著减少分析时间。识别后通常有两条路：

- 算法可逆：提取 key、密文和参数，写解密脚本。
- 算法不可逆或只有校验：还原约束，用爆破、字典、Z3 或查表。

### Base64

Base64 是一种基于 64 个可打印字符表示二进制数据的方法。转换时每 3 字节组成 24 位缓冲区，每次取 6 bit，映射到索引表。

典型识别特征：

```text
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```

如果二进制中能找到这样的索引表，再结合代码中“按 6 bit 切分、查表、补 `=`”的逻辑，基本可以判定为 Base64。

变种 Base64 主要修改索引表。处理方式：

1. 提取自定义表。
2. 建立标准表与自定义表的映射。
3. 如果是编码结果，按自定义表解码。

Python 骨架：

```python
import base64
import string

std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
custom = "..."  # 从程序中提取
cipher = "..."

trans = str.maketrans(custom, std)
print(base64.b64decode(cipher.translate(trans)))
```

### TEA / XTEA / XXTEA

TEA 的最主要识别特征是 magic number：

```text
0x9e3779b9
```

典型加密结构：

```c
uint32_t delta = 0x9e3779b9;
for (i = 0; i < 32; i++) {
    sum += delta;
    v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
}
```

典型解密结构：

```c
sum = 0xC6EF3720;
for (i = 0; i < 32; i++) {
    v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
    sum -= delta;
}
```

解题流程：

1. 确认轮数、delta、key、输入分组大小。
2. 判断是否魔改移位量、常量、轮数或 key 调度。
3. 提取密文。
4. 写逆运算，注意 32 位无符号溢出：

```python
MASK = 0xffffffff

def dec(v0, v1, k):
    delta = 0x9e3779b9
    s = (delta * 32) & MASK
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + s) ^ ((v0 >> 5) + k[3]))) & MASK
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + s) ^ ((v1 >> 5) + k[1]))) & MASK
        s = (s - delta) & MASK
    return v0, v1
```

### RC4

RC4 是流加密算法，加解密使用同一个密钥。识别特征很明显：

- 初始化长度为 256 的 S 盒。
- 第一个循环 `S[i] = i`。
- 第二个循环用 key 打乱 S 盒，交换 `S[i]` 和 `S[j]`。
- 加解密阶段不断更新 `i/j`，交换 S 盒，再与 `S[(S[i]+S[j])%256]` 异或。

KSA：

```c
for i from 0 to 255:
    S[i] = i
j = 0
for i from 0 to 255:
    j = (j + S[i] + key[i % keylen]) % 256
    swap(S[i], S[j])
```

PRGA：

```c
i = 0
j = 0
while data:
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    swap(S[i], S[j])
    k = S[(S[i] + S[j]) % 256]
    out = input ^ k
```

Python 骨架：

```python
def rc4(data, key):
    s = list(range(256))
    j = 0
    key = list(key)
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]

    i = j = 0
    out = []
    for b in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)
```

### MD5 / Hash 校验

MD5 是哈希算法，不可直接解密。识别特征：

- 初始化值：`0x67452301`、`0xEFCDAB89`、`0x98BADCFE`、`0x10325476`。
- 64 轮循环。
- 大量固定移位和正弦常量表。
- 输出 16 字节或 32 位十六进制字符串。

解题方式：

- 如果输入空间小，爆破。
- 如果是已知明文格式，按格式约束爆破。
- 如果只是调用标准库 `md5(input)`，可直接提取目标 hash 查字典。
- 如果题目魔改 MD5，通常要还原魔改位置，再写对应计算脚本。

### AES / DES 等块密码

AES 识别特征：

- S-box / inverse S-box 表。
- `SubBytes`、`ShiftRows`、`MixColumns`、`AddRoundKey`。
- 10/12/14 轮。
- 16 字节分组。

如果是标准 AES：

1. 找 key、IV、模式、padding。
2. 用 Python Crypto 库解密。

如果是魔改 AES：

1. 先判断改的是 S-box、轮数、key schedule 还是最后比较。
2. 静态还原关键表。
3. 必要时动态 dump 中间 state。

## 迷宫题

迷宫题有几个稳定特征：

- 内存中布置一张地图。
- 用户输入被限制在少数几个字符范围内。
- 通常只有一个入口和一个出口。
- 程序维护 X/Y 坐标或一维位置。

地图形式：

- 可见字符：`#`、`*`、`.`、`S`、`E` 等。
- 不可见十六进制值。
- 一条很长的字符串。
- 按行分开布置，但行顺序可能被打乱，需要根据行号还原。

方向字符：

- `w/s/a/d`
- `h/j/k/l`
- `L/R/U/D`
- 也可能是自定义字符，需分析每个字符对坐标的影响。

### 解题流程

1. `strings` 或 IDA `.rodata` 找地图字符串。
2. 如果行乱序，回到伪 C 看每行被写入的行号。
3. 还原完整二维地图。
4. 找移动逻辑：每个输入字符如何改变 `x/y`。
5. 找成功条件：出口坐标、目标字符或计分条件。
6. 写 BFS/DFS 求路径。
7. 把路径字符喂给程序验证。

### 例题流程

Volga Quals CTF 2014 Reverse 100：

- 地图按行乱序布置。
- 字符是 `#` 和 `*`。
- 在 `.rodata` 选择地图字符串，`Shift+E` 提取数据。
- 回到 IDA 伪 C，按行号重新排序组合地图。
- 移动字符为 `L/R/U/D`，分别对应左、右、上、下。
- 成功条件为：

```c
pos_x == 89 && pos_y == 28
```

### BFS 骨架

```python
from collections import deque

maze = [list(line.rstrip("\n")) for line in open("maze.txt")]
h, w = len(maze), len(maze[0])
start = (0, 0)
end = (89, 28)

dirs = {
    "L": (0, -1),
    "R": (0, 1),
    "U": (-1, 0),
    "D": (1, 0),
}

q = deque([(start, "")])
vis = {start}

while q:
    (x, y), path = q.popleft()
    if (x, y) == end:
        print(path)
        break
    for ch, (dx, dy) in dirs.items():
        nx, ny = x + dx, y + dy
        if not (0 <= nx < h and 0 <= ny < w):
            continue
        if maze[nx][ny] == "#":
            continue
        if (nx, ny) in vis:
            continue
        vis.add((nx, ny))
        q.append(((nx, ny), path + ch))
```

注意坐标顺序。程序里的 `pos_x/pos_y` 未必等于 Python 里的 `row/col`，要根据移动逻辑确认。

## 虚拟机题

VM 题的核心是程序自己实现了一个解释器。真实逻辑不直接在原生指令里，而是隐藏在自定义 bytecode 中。

识别特征：

- 有 `vm_pc`、`vm_sp`、寄存器数组或多个全局寄存器变量。
- 有 opcode 分发：大量 `if/else if`、`switch` 或跳表。
- 有取指、译码、执行循环。
- 输入被转换成 bytecode 或 bytecode 使用输入作为数据。
- 出现自定义 `push/pop/mov/cmp/xor/check`。

### 通用流程

1. 找用户输入入口。
2. 找输入预处理，例如 `input[i] ^= i`。
3. 找 VM 初始化：寄存器、栈、pc、sp、flags。
4. 找 VM 主循环。
5. 还原 opcode 表。
6. 还原每条指令语义。
7. 找 `check` 指令或成功分支。
8. 写解释器、反解释器或 keygen。

### FuelVM 分析要点

程序用 `GetDlgItemTextA()` 获取两个输入：

```asm
push 0Ch
push offset inputName
push 3F8h
push [ebp+hWnd]
call GetDlgItemTextA

push 0Ch
push offset inputKey
push 3F9h
push [ebp+hWnd]
call GetDlgItemTextA
```

然后调用 `process_input`。输入要求：

```text
inputName 和 inputKey 的长度均不少于 7
```

用户名预处理：

```c
for (i = 0; i <= lenOfName; ++i) {
    inputName[i] ^= i;
}
```

Python 对应：

```python
def obfuscate(username):
    return "".join(chr(ord(username[i]) ^ i) for i in range(len(username)))
```

### SEH 与反调试处理

FuelVM 中通过 SEH 和 `int 3` 进入 VM：

```asm
push offset seh_handler
push large dword ptr fs:0
mov large fs:0, esp
call initVM
int 3
```

IDA 没有正确识别异常处理函数，需要按 `c` 把数据转代码。过程中还有 `jmp loc+2` 这类跳到指令中间的反调试/反反汇编技巧，处理方式是 nop 掉相应字节，再重新创建函数。

### 恢复堆栈平衡

IDA F5 失败时，可以通过显示 stack pointer 找到不平衡位置，把错误的多次 `leave` 改成 `retn`，再重新创建函数，使 `vm_main` 能正常反编译。

处理方法：

1. `Options -> General` 勾选 stack pointer。
2. 找到 SP 不平衡位置。
3. patch 明显错误的 `leave/retn/jmp`。
4. 重新定义函数范围。
5. 再 F5。

### opcode 表

FuelVM 还原出的 opcode：

| opcode | value |
| --- | --- |
| push | `0x0a` |
| pop | `0x0b` |
| mov | `0x0c` |
| cmp | `0x0d` |
| inc | `0x0e` |
| dec | `0x0f` |
| and | `0x1b` |
| or | `0x1c` |
| xor | `0x1d` |
| check | `0xff` |

VM 初始化：

```c
r1 = 0;
r2 = 0;
r3 = 0;
r4 = inputName[cur_index];
vm_sp = 0x32;
vm_pc = 0;
vm_flags_zf = 0;
vm_flags_sf = 0;
++cur_index;
```

`check` 指令逻辑：

```c
v1 = r1;
if ((unsigned char)r1 < 0x21)
    v1 = r1 + 0x21;

if (v1 == inputKey[cur_index]) {
    if (cur_index >= lenOfName)
        success();
    else
        initVM();
} else {
    fail();
}
```

因为 `process_input` 中执行了两次 `initVM()`，所以 `inputKey` 前两位可以是任意字符。

### VM 题脚本策略

三种常见求法：

- 直接解释执行 bytecode，枚举输入或输出 key。
- 反向执行 check 逻辑，从目标倒推输入。
- 把每条 VM 指令翻译成 Z3 约束。

解释器骨架：

```python
pc = 0
sp = 0x32
regs = [0, 0, 0, 0]
stack = [0] * 0x100

while True:
    op = code[pc]
    pc += 1

    if op == 0x0a:      # push
        stack[sp] = regs[0]
        sp -= 1
    elif op == 0x0b:    # pop
        sp += 1
        regs[0] = stack[sp]
    elif op == 0x1d:    # xor
        regs[0] ^= regs[1]
    elif op == 0xff:    # check
        break
```

## 总结

算法、迷宫、VM 的共同点是：不要只盯着反编译结果本身，而要把程序里的“规则”抽出来。

- 算法题抽 key、表、常量、轮数、密文。
- 迷宫题抽地图、方向、起点终点、代价规则。
- VM 题抽寄存器、栈、opcode、指令语义、check 条件。

抽象规则之后，解题就变成写 Python。
