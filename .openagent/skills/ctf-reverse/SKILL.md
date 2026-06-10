---
name: ctf-reverse
description: "必须用于授权 CTF reverse engineering：checker binary、PE/ELF/APK、strings/XREF、encoding/crypto、maze、VM bytecode、obfuscation、anti-debug、SMC、unpacking、Z3、angr、Unicorn、solver script。"
---

# CTF REVERSE

## 强制边界

- 只处理授权 CTF、lab、wargame、training 目标。
- 必须围绕 flag/checker 路径分析；禁止翻译无关 UI、库函数和错误处理。
- 必须先定位校验逻辑，再写 solver；禁止先写大而全模拟器。

## 必须执行顺序

1. 必须调用 `ctf_status`，除非本轮会话已经调用过。
2. reverse 子类型不明确时，必须先读取 `../../docs/REVERSE/index.md`。
3. 必须调用 `ctf_reverse`，`deep=false`，收集 file type、strings、headers、symbols、可疑字符串。
4. 出现 packed、高熵、OEP、anti-debug 证据时，必须先调用 `ctf_unpack action="identify"`，禁止直接陷入静态反编译。
5. 必须用 `ctf_note` 记录当前路径和证据。

## 专题文档强制路由

必须只读取和证据匹配的专题：

- Plain checker、strings、XREF、输入函数、比较函数、动态调试、solver skeleton：读取 `../../docs/REVERSE/basic-workflow.md`。
- Base64、TEA/XTEA/XXTEA、RC4、MD5/hash、AES/DES、maze、VM/opcode dispatcher：读取 `../../docs/REVERSE/algorithm-maze-vm.md`。
- 花指令、SMC、控制流平坦化、anti-debug、PE shell/unpacking、OEP、IAT repair：读取 `../../docs/REVERSE/obfuscation-anti-debug-unpack.md`。
- Z3、angr、Unicorn、LD_PRELOAD、IDA/Ghidra automation：读取 `../../docs/REVERSE/tools.md`。

## 工具调用协议

- Baseline 必须使用 `ctf_reverse`。
- packed/obfuscated startup 必须先用 `ctf_unpack identify`。
- 只有确认 UPX 时，才允许调用 `ctf_unpack action="upx"`。
- 需要 OEP、mapping、运行时解密代码或内存证据时，必须使用 `ctf_unpack action="dump"`。
- 短命令、solver 草稿、局部复现必须使用 `ctf_run`。
- 候选 flag 提取或验证必须使用 `ctf_flag`。

禁止用宽泛 shell 探测替代专用 CTF 工具；shell 只能用于短小、可复现、范围明确的检查。

## 分析硬规则

1. 必须先定位输入和比较路径：strings、prompt、`strcmp/memcmp`、WinAPI input、success/fail branch、syscall pattern。
2. 必须分类 transform：
   - table/magic constants：算法识别；
   - map/direction/state：maze 或 state machine；
   - `pc/sp/register/opcode`：VM；
   - 异常 CFG 或运行时代码改写：obfuscation/SMC；
   - 大量算术/bit 约束：Z3 或 angr。
3. 必须只还原求 flag 必需逻辑。
4. 原始代码依赖 C 整数语义时，solver 必须保持精确 bit width 和 overflow 行为。
5. solver 结果必须通过原程序或等价 checker 验证；验证后必须调用 `ctf_flag`。

## 记录与完成条件

必须用 `ctf_note` 记录：

- validation function/address；
- recognized algorithm/constants；
- extracted table、bytecode、maze、constraints；
- solver assumption 和验证结果。

最终回答必须包含最小复现：输入文件/binary、命令或 solver、成功输出证据和 flag 候选。
