# REVERSE 题型索引

REVERSE 的核心是把程序行为还原出来，再写脚本求输入或 flag。当前知识库可以按四类使用：

1. 常规逆向：字符串、交叉引用、关键函数、动态调试。
2. 算法题：识别编码/加密/校验逻辑，逆运算或约束求解。
3. 结构题：迷宫、VM、字节码、状态机。
4. 对抗题：花指令、SMC、控制流平坦化、反调试、壳。

## 快速判断表

| 现象 | 题型 | 解法入口 |
| --- | --- | --- |
| 普通 checker，输入后比较结果 | 常规逆向 | [常规逆向流程](./basic-workflow.md) |
| 有明显字符串提示，能 XREF 到判断函数 | 常规定位 | [定位关键代码](./basic-workflow.md#定位关键代码) |
| 有 Base64 表、TEA delta、RC4 S 盒、MD5 常量 | 编码/加密识别 | [编码与加密识别](./algorithm-maze-vm.md#编码与加密识别) |
| 地图字符、坐标、方向键 | 迷宫题 | [迷宫题](./algorithm-maze-vm.md#迷宫题) |
| `opcode`、`pc/sp`、寄存器数组、分发循环 | VM 题 | [虚拟机题](./algorithm-maze-vm.md#虚拟机题) |
| IDA 无法 F5，`jmp loc+1` 或 call/ret 扭曲控制流 | 花指令 | [花指令](./obfuscation-anti-debug-unpack.md#花指令) |
| 程序运行时改写代码段，静态反汇编是垃圾数据 | SMC | [SMC](./obfuscation-anti-debug-unpack.md#smc) |
| CFG 有主分发器，状态变量控制所有块 | 控制流平坦化 | [控制流平坦化](./obfuscation-anti-debug-unpack.md#控制流平坦化) |
| `ptrace`、`int 3`、TLS、异常链、断点检测 | 反调试 | [反调试](./obfuscation-anti-debug-unpack.md#反调试) |
| PE 有壳、OEP、IAT 问题 | 脱壳 | [脱壳](./obfuscation-anti-debug-unpack.md#脱壳) |
| 大量线性约束或 bit 运算约束 | Z3 | [Z3](./tools.md#z3) |
| 想自动找成功路径/避开失败路径 | angr | [angr](./tools.md#angr) |
| 想模拟一段机器码或混淆函数 | Unicorn | [Unicorn](./tools.md#unicorn) |

## 常用命令

```sh
file ./re
strings -a ./re | less
checksec ./re
readelf -a ./re
objdump -d -M intel ./re | less
binwalk ./file
```
