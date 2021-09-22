// SPDX-License-Identifier: GPL-2.0
/*
 * Dynamic function tracing support.
 *
 * Copyright (C) 2007-2008 Steven Rostedt <srostedt@redhat.com>
 *
 * Thanks goes to Ingo Molnar, for suggesting the idea.
 * Mathieu Desnoyers, for suggesting postponing the modifications.
 * Arjan van de Ven, for keeping me straight, and explaining to me
 * the dangers of modifying code on the run.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/memory.h>

#include <trace/syscall.h>

#include <asm/set_memory.h>
#include <asm/kprobes.h>
#include <asm/ftrace.h>
#include <asm/nops.h>
#include <asm/text-patching.h>

#ifdef CONFIG_DYNAMIC_FTRACE

int ftrace_arch_code_modify_prepare(void)
    __acquires(&text_mutex)
{
	/*
	 * Need to grab text_mutex to prevent a race from module loading
	 * and live kernel patching from changing the text permissions while
	 * ftrace has it set to "read/write".
	 */
	mutex_lock(&text_mutex);
	set_kernel_text_rw();
	set_all_modules_text_rw();
	return 0;
}

int ftrace_arch_code_modify_post_process(void)
    __releases(&text_mutex)
{
	set_all_modules_text_ro();
	set_kernel_text_ro();
	mutex_unlock(&text_mutex);
	return 0;
}

union ftrace_code_union {
	char code[MCOUNT_INSN_SIZE];
	struct {
		unsigned char op;
		int offset;
	} __attribute__((packed));
};

static int ftrace_calc_offset(long ip, long addr)
{
	return (int)(addr - ip);
}

static unsigned char *
ftrace_text_replace(unsigned char op, unsigned long ip, unsigned long addr)
{
	static union ftrace_code_union calc;

	calc.op		= op;
	calc.offset	= ftrace_calc_offset(ip + MCOUNT_INSN_SIZE, addr);

	return calc.code;
}

/*生成替换指令, 0xe8为call @addr*/
static unsigned char *
ftrace_call_replace(unsigned long ip, unsigned long addr)
{
	return ftrace_text_replace(0xe8, ip, addr);
}

static inline int
within(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr < end;
}

static unsigned long text_ip_addr(unsigned long ip)
{
	/*
	 * On x86_64, kernel text mappings are mapped read-only, so we use
	 * the kernel identity mapping instead of the kernel text mapping
	 * to modify the kernel text.
	 *
	 * 内核有identity mapping (物理地址和虚拟地址中间差了一个offset)
	 * 同时还有text mapping (虚拟地址为 _text , _etext), 这个是映射代码段的
	 * 也就是说 代码段会被映射到两个mapping上
	 * 因为text mapping 是只读的, 但是我们需要改内存,所以只能通过identity mapping
	 * 所以 我们需要如下转换:
	 * text mapping ===> phy addr ===> identity mapping
	 * 最终返回 identity mapping 中的虚拟地址
	 * 
	 *
	 * For 32bit kernels, these mappings are same and we can use
	 * kernel identity mapping to modify code.
	 */
	if (within(ip, (unsigned long)_text, (unsigned long)_etext))
		ip = (unsigned long)__va(__pa_symbol(ip));

	return ip;
}

static const unsigned char *ftrace_nop_replace(void)
{
	return ideal_nops[NOP_ATOMIC5];
}

static int
ftrace_modify_code_direct(unsigned long ip, unsigned const char *old_code,
		   unsigned const char *new_code)
{
	unsigned char replaced[MCOUNT_INSN_SIZE];

	ftrace_expected = old_code;

	/*
	 * Note:
	 * We are paranoid about modifying text, as if a bug was to happen, it
	 * could cause us to read or write to someplace that could cause harm.
	 * Carefully read and modify the code with probe_kernel_*(), and make
	 * sure what we read is what we expected it to be before modifying it.
	 */

	/* read the text we want to modify */
	if (probe_kernel_read(replaced, (void *)ip, MCOUNT_INSN_SIZE))
		return -EFAULT;

	/*确定一下,   被替换的指令就是call __fentry__ 否则替换错了就傻逼了*/
	/* Make sure it is what we expect it to be */
	if (memcmp(replaced, old_code, MCOUNT_INSN_SIZE) != 0)
		return -EINVAL;

	ip = text_ip_addr(ip);

	/* replace the text with the new text */
	/*写入*/
	if (probe_kernel_write((void *)ip, new_code, MCOUNT_INSN_SIZE))
		return -EPERM;

	sync_core();

	return 0;
}

int ftrace_make_nop(struct module *mod,
		    struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned const char *new, *old;
	unsigned long ip = rec->ip;

	/*生成 ip 为 @ip 地址上 call @addr 的 call执行*/
	old = ftrace_call_replace(ip, addr);
	new = ftrace_nop_replace();

	/*
	 * On boot up, and when modules are loaded, the MCOUNT_ADDR
	 * is converted to a nop, and will never become MCOUNT_ADDR
	 * again. This code is either running before SMP (on boot up)
	 * or before the code will ever be executed (module load).
	 * We do not want to use the breakpoint version in this case,
	 * just modify the code directly.
	 */
	if (addr == MCOUNT_ADDR)
		return ftrace_modify_code_direct(rec->ip, old, new);

	ftrace_expected = NULL;

	/* Normal cases use add_brk_on_nop */
	WARN_ONCE(1, "invalid use of ftrace_make_nop");
	return -EINVAL;
}

int ftrace_make_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned const char *new, *old;
	unsigned long ip = rec->ip;

	old = ftrace_nop_replace();
	new = ftrace_call_replace(ip, addr);

	/* Should only be called when module is loaded */
	return ftrace_modify_code_direct(rec->ip, old, new);
}

/*
 * The modifying_ftrace_code is used to tell the breakpoint
 * handler to call ftrace_int3_handler(). If it fails to
 * call this handler for a breakpoint added by ftrace, then
 * the kernel may crash.
 *
 * As atomic_writes on x86 do not need a barrier, we do not
 * need to add smp_mb()s for this to work. It is also considered
 * that we can not read the modifying_ftrace_code before
 * executing the breakpoint. That would be quite remarkable if
 * it could do that. Here's the flow that is required:
 *
 *   CPU-0                          CPU-1
 *
 * atomic_inc(mfc);
 * write int3s
 *				<trap-int3> // implicit (r)mb
 *				if (atomic_read(mfc))
 *					call ftrace_int3_handler()
 *
 * Then when we are finished:
 *
 * atomic_dec(mfc);
 *
 * If we hit a breakpoint that was not set by ftrace, it does not
 * matter if ftrace_int3_handler() is called or not. It will
 * simply be ignored. But it is crucial that a ftrace nop/caller
 * breakpoint is handled. No other user should ever place a
 * breakpoint on an ftrace nop/caller location. It must only
 * be done by this code.
 */
atomic_t modifying_ftrace_code __read_mostly;

static int
ftrace_modify_code(unsigned long ip, unsigned const char *old_code,
		   unsigned const char *new_code);

/*
 * Should never be called:
 *  As it is only called by __ftrace_replace_code() which is called by
 *  ftrace_replace_code() that x86 overrides, and by ftrace_update_code()
 *  which is called to turn mcount into nops or nops into function calls
 *  but not to convert a function from not using regs to one that uses
 *  regs, which ftrace_modify_call() is for.
 */
int ftrace_modify_call(struct dyn_ftrace *rec, unsigned long old_addr,
				 unsigned long addr)
{
	WARN_ON(1);
	ftrace_expected = NULL;
	return -EINVAL;
}

static unsigned long ftrace_update_func;
static unsigned long ftrace_update_func_call;


/*ip 中放入 new指令*/
static int update_ftrace_func(unsigned long ip, void *new)
{
	unsigned char old[MCOUNT_INSN_SIZE];
	int ret;

	memcpy(old, (void *)ip, MCOUNT_INSN_SIZE);

	ftrace_update_func = ip;
	/* Make sure the breakpoints see the ftrace_update_func update */
	smp_wmb();

	/* See comment above by declaration of modifying_ftrace_code */
	atomic_inc(&modifying_ftrace_code);

	ret = ftrace_modify_code(ip, old, new);

	atomic_dec(&modifying_ftrace_code);

	return ret;
}

/*
 * ftrace_caller 中 ftrace_call 指向需要替换指令的地方
 * ftrace_regs_caller 中 ftrace_regs_call 指向需要替换指令的地方
 *
 * 将 call @func 覆盖 ftrace_call和ftrace_regs_call
 */
int ftrace_update_ftrace_func(ftrace_func_t func)
{
	unsigned long ip = (unsigned long)(&ftrace_call);
	unsigned char *new;
	int ret;

	ftrace_update_func_call = (unsigned long)func;

	/*new 为替换的指令*/
	new = ftrace_call_replace(ip, (unsigned long)func);
	/*把new 指令写入ip指向的地址中, 并更新 ftrace_update_func*/
	ret = update_ftrace_func(ip, new);

	/* Also update the regs callback function */
	if (!ret) {
		ip = (unsigned long)(&ftrace_regs_call);
		new = ftrace_call_replace(ip, (unsigned long)func);
		/*这里又会改动 ftrace_update_func */
		ret = update_ftrace_func(ip, new);
	}

	return ret;
}

static nokprobe_inline int is_ftrace_caller(unsigned long ip)
{
	if (ip == ftrace_update_func)
		return 1;

	return 0;
}

/*
 * A breakpoint was added to the code address we are about to
 * modify, and this is the handle that will just skip over it.
 * We are either changing a nop into a trace call, or a trace
 * call to a nop. While the change is taking place, we treat
 * it just like it was a nop.
 */
int ftrace_int3_handler(struct pt_regs *regs)
{
	unsigned long ip;

	if (WARN_ON_ONCE(!regs))
		return 0;

	ip = regs->ip - INT3_INSN_SIZE;

	if (ftrace_location(ip)) {
		int3_emulate_call(regs, (unsigned long)ftrace_regs_caller);
		return 1;
	} else if (is_ftrace_caller(ip)) {
		if (!ftrace_update_func_call) {
			int3_emulate_jmp(regs, ip + CALL_INSN_SIZE);
			return 1;
		}
		int3_emulate_call(regs, ftrace_update_func_call);
		return 1;
	}

	return 0;
}
NOKPROBE_SYMBOL(ftrace_int3_handler);

static int ftrace_write(unsigned long ip, const char *val, int size)
{
	ip = text_ip_addr(ip);

	if (probe_kernel_write((void *)ip, val, size))
		return -EPERM;

	return 0;
}

/*如果@ip 上的指令为 old 则替换为int3 指令*/
static int add_break(unsigned long ip, const char *old)
{
	unsigned char replaced[MCOUNT_INSN_SIZE];
	unsigned char brk = BREAKPOINT_INSTRUCTION;

	if (probe_kernel_read(replaced, (void *)ip, MCOUNT_INSN_SIZE))
		return -EFAULT;

	ftrace_expected = old;

	/* Make sure it is what we expect it to be */
	if (memcmp(replaced, old, MCOUNT_INSN_SIZE) != 0)
		return -EINVAL;

	return ftrace_write(ip, &brk, 1);
}

/*如果是call @addr 指令,则替换为break*/
static int add_brk_on_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned const char *old;
	unsigned long ip = rec->ip;

	old = ftrace_call_replace(ip, addr);

	return add_break(rec->ip, old);
}

/*如果是nop  替换为brk*/
static int add_brk_on_nop(struct dyn_ftrace *rec)
{
	unsigned const char *old;

	old = ftrace_nop_replace();

	return add_break(rec->ip, old);
}

static int add_breakpoints(struct dyn_ftrace *rec, bool enable)
{
	unsigned long ftrace_addr;
	int ret;

	ftrace_addr = ftrace_get_addr_curr(rec);

	ret = ftrace_test_record(rec, enable);

	switch (ret) {
	case FTRACE_UPDATE_IGNORE:
		return 0;

	case FTRACE_UPDATE_MAKE_CALL:
		/* converting nop to call */
		return add_brk_on_nop(rec);

	case FTRACE_UPDATE_MODIFY_CALL:
	case FTRACE_UPDATE_MAKE_NOP:
		/* converting a call to a nop */
		return add_brk_on_call(rec, ftrace_addr);
	}
	return 0;
}

/*
 * On error, we need to remove breakpoints. This needs to
 * be done caefully. If the address does not currently have a
 * breakpoint, we know we are done. Otherwise, we look at the
 * remaining 4 bytes of the instruction. If it matches a nop
 * we replace the breakpoint with the nop. Otherwise we replace
 * it with the call instruction.
 */
static int remove_breakpoint(struct dyn_ftrace *rec)
{
	unsigned char ins[MCOUNT_INSN_SIZE];
	unsigned char brk = BREAKPOINT_INSTRUCTION;
	const unsigned char *nop;
	unsigned long ftrace_addr;
	unsigned long ip = rec->ip;

	/* If we fail the read, just give up */
	if (probe_kernel_read(ins, (void *)ip, MCOUNT_INSN_SIZE))
		return -EFAULT;

	/* If this does not have a breakpoint, we are done */
	if (ins[0] != brk)
		return 0;

	nop = ftrace_nop_replace();

	/*
	 * If the last 4 bytes of the instruction do not match
	 * a nop, then we assume that this is a call to ftrace_addr.
	 */
	if (memcmp(&ins[1], &nop[1], MCOUNT_INSN_SIZE - 1) != 0) {
		/*
		 * For extra paranoidism, we check if the breakpoint is on
		 * a call that would actually jump to the ftrace_addr.
		 * If not, don't touch the breakpoint, we make just create
		 * a disaster.
		 */
		ftrace_addr = ftrace_get_addr_new(rec);
		nop = ftrace_call_replace(ip, ftrace_addr);

		if (memcmp(&ins[1], &nop[1], MCOUNT_INSN_SIZE - 1) == 0)
			goto update;

		/* Check both ftrace_addr and ftrace_old_addr */
		ftrace_addr = ftrace_get_addr_curr(rec);
		nop = ftrace_call_replace(ip, ftrace_addr);

		ftrace_expected = nop;

		if (memcmp(&ins[1], &nop[1], MCOUNT_INSN_SIZE - 1) != 0)
			return -EINVAL;
	}

 update:
	return ftrace_write(ip, nop, 1);
}

/*对指令的第一个字节不做修改,应该是为了后续原子操作*/
static int add_update_code(unsigned long ip, unsigned const char *new)
{
	/* skip breakpoint */
	ip++;
	new++;
	return ftrace_write(ip, new, MCOUNT_INSN_SIZE - 1);
}

static int add_update_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long ip = rec->ip;
	unsigned const char *new;

	new = ftrace_call_replace(ip, addr);
	return add_update_code(ip, new);
}

static int add_update_nop(struct dyn_ftrace *rec)
{
	unsigned long ip = rec->ip;
	unsigned const char *new;

	new = ftrace_nop_replace();
	return add_update_code(ip, new);
}

/*
 * 根据rec中的flags 拿到一个合适的ftrace_addr, 然后根据ret值更新为不同
 * 的指令
 * @enable = FTRACE_MODIFY_ENABLE_FL
 */
static int add_update(struct dyn_ftrace *rec, bool enable)
{
	unsigned long ftrace_addr;
	int ret;

	/* 这个rec 使能了吗? 需要修改吗? 根据rec->flags 来确定
	 * 有需要修改的话就继续修改, 否则 FTRACE_UPDATE_IGNORE
	 */
	ret = ftrace_test_record(rec, enable);

	ftrace_addr  = ftrace_get_addr_new(rec);

	switch (ret) {
	case FTRACE_UPDATE_IGNORE:
		return 0;

	case FTRACE_UPDATE_MODIFY_CALL:
	case FTRACE_UPDATE_MAKE_CALL:
		/* converting nop to call */
		return add_update_call(rec, ftrace_addr);

	case FTRACE_UPDATE_MAKE_NOP:
		/* converting a call to a nop */
		return add_update_nop(rec);
	}

	return 0;
}

static int finish_update_call(struct dyn_ftrace *rec, unsigned long addr)
{
	unsigned long ip = rec->ip;
	unsigned const char *new;

	new = ftrace_call_replace(ip, addr);

	return ftrace_write(ip, new, 1);
}

static int finish_update_nop(struct dyn_ftrace *rec)
{
	unsigned long ip = rec->ip;
	unsigned const char *new;

	new = ftrace_nop_replace();

	return ftrace_write(ip, new, 1);
}

/*把第一个字节恢复成正常的指令*/
static int finish_update(struct dyn_ftrace *rec, bool enable)
{
	unsigned long ftrace_addr;
	int ret;

	ret = ftrace_update_record(rec, enable);

	ftrace_addr = ftrace_get_addr_new(rec);

	switch (ret) {
	case FTRACE_UPDATE_IGNORE:
		return 0;

	case FTRACE_UPDATE_MODIFY_CALL:
	case FTRACE_UPDATE_MAKE_CALL:
		/* converting nop to call */
		return finish_update_call(rec, ftrace_addr);

	case FTRACE_UPDATE_MAKE_NOP:
		/* converting a call to a nop */
		return finish_update_nop(rec);
	}

	return 0;
}

static void do_sync_core(void *data)
{
	sync_core();
}

static void run_sync(void)
{
	int enable_irqs;

	/* No need to sync if there's only one CPU */
	if (num_online_cpus() == 1)
		return;

	enable_irqs = irqs_disabled();

	/* We may be called with interrupts disabled (on bootup). */
	if (enable_irqs)
		local_irq_enable();
	on_each_cpu(do_sync_core, NULL, 1);
	if (enable_irqs)
		local_irq_disable();
}

/*
 * 对每个dyn_ftrace rec , !!!!只有当有需要时!!!! 才修改其指令
 * 是否有需要 需要看 ftrace_test_record 的返回值
 */
void ftrace_replace_code(int enable)
{
	struct ftrace_rec_iter *iter;
	struct dyn_ftrace *rec;
	const char *report = "adding breakpoints";
	int count = 0;
	int ret;

	/*
	 * MCOUNT_INSN 这条指令的第一个字节替换为断点指令
	 * 这样是为了让进程进入之后一直中断
	 */
	for_ftrace_rec_iter(iter) {
		rec = ftrace_rec_iter_record(iter);

		ret = add_breakpoints(rec, enable);
		if (ret)
			goto remove_breakpoints;
		count++;
	}

	run_sync();

	report = "updating code";
	count = 0;

	for_ftrace_rec_iter(iter) {
		rec = ftrace_rec_iter_record(iter);
		/*
		 * 这里会强制替换成call指令,但是只是替换[1 , MCOUNT_INSN_SIZE),
		 * 0 byte 为 breakpoint 指令
		 */
		ret = add_update(rec, enable);
		if (ret)
			goto remove_breakpoints;
		count++;
	}

	run_sync();

	report = "removing breakpoints";
	count = 0;

	for_ftrace_rec_iter(iter) {
		rec = ftrace_rec_iter_record(iter);
		/*
		 * 这里会对每个rec 设置FTRACE_FL_ENABLED, 并生成最终的跳转代码
		 * 然后恢复 第一个字节 变为真正的jump 指令
		 */
		ret = finish_update(rec, enable);
		if (ret)
			goto remove_breakpoints;
		count++;
	}

	run_sync();

	return;

 remove_breakpoints:
	pr_warn("Failed on %s (%d):\n", report, count);
	ftrace_bug(ret, rec);
	for_ftrace_rec_iter(iter) {
		rec = ftrace_rec_iter_record(iter);
		/*
		 * Breakpoints are handled only when this function is in
		 * progress. The system could not work with them.
		 */
		if (remove_breakpoint(rec))
			BUG();
	}
	run_sync();
}

static int
ftrace_modify_code(unsigned long ip, unsigned const char *old_code,
		   unsigned const char *new_code)
{
	int ret;

	ret = add_break(ip, old_code);
	if (ret)
		goto out;

	run_sync();

	ret = add_update_code(ip, new_code);
	if (ret)
		goto fail_update;

	run_sync();

	ret = ftrace_write(ip, new_code, 1);
	/*
	 * The breakpoint is handled only when this function is in progress.
	 * The system could not work if we could not remove it.
	 */
	BUG_ON(ret);
 out:
	run_sync();
	return ret;

 fail_update:
	/* Also here the system could not work with the breakpoint */
	if (ftrace_write(ip, old_code, 1))
		BUG();
	goto out;
}

void arch_ftrace_update_code(int command)
{
	/* See comment above by declaration of modifying_ftrace_code */
	atomic_inc(&modifying_ftrace_code);

	ftrace_modify_all_code(command);

	atomic_dec(&modifying_ftrace_code);
}

int __init ftrace_dyn_arch_init(void)
{
	return 0;
}

/* Currently only x86_64 supports dynamic trampolines */
#ifdef CONFIG_X86_64

#ifdef CONFIG_MODULES
#include <linux/moduleloader.h>
/* Module allocation simplifies allocating memory for code */
static inline void *alloc_tramp(unsigned long size)
{
	return module_alloc(size);
}
static inline void tramp_free(void *tramp)
{
	module_memfree(tramp);
}
#else
/* Trampolines can only be created if modules are supported */
static inline void *alloc_tramp(unsigned long size)
{
	return NULL;
}
static inline void tramp_free(void *tramp) { }
#endif

/* Defined as markers to the end of the ftrace default trampolines */
extern void ftrace_regs_caller_end(void);
extern void ftrace_epilogue(void);
extern void ftrace_caller_op_ptr(void);
extern void ftrace_regs_caller_op_ptr(void);

/* movq function_trace_op(%rip), %rdx */
/* 0x48 0x8b 0x15 <offset-to-ftrace_trace_op (4 bytes)> */
#define OP_REF_SIZE	7

/*
 * The ftrace_ops is passed to the function callback. Since the
 * trampoline only services a single ftrace_ops, we can pass in
 * that ops directly.
 *
 * The ftrace_op_code_union is used to create a pointer to the
 * ftrace_ops that will be passed to the callback function.
 */
union ftrace_op_code_union {
	char code[OP_REF_SIZE];
	struct {
		char op[3];
		int offset;
	} __attribute__((packed));
};

#define RET_SIZE		1

static unsigned long
create_trampoline(struct ftrace_ops *ops, unsigned int *tramp_size)
{
	unsigned long start_offset;
	unsigned long end_offset;
	unsigned long op_offset;
	unsigned long offset;
	unsigned long npages;
	unsigned long size;
	unsigned long retq;
	unsigned long *ptr;
	void *trampoline;
	void *ip;
	/* 48 8b 15 <offset> is movq <offset>(%rip), %rdx */
	unsigned const char op_ref[] = { 0x48, 0x8b, 0x15 };
	union ftrace_op_code_union op_ptr;
	int ret;

	if (ops->flags & FTRACE_OPS_FL_SAVE_REGS) {
		start_offset = (unsigned long)ftrace_regs_caller;
		end_offset = (unsigned long)ftrace_regs_caller_end;
		op_offset = (unsigned long)ftrace_regs_caller_op_ptr;
	} else {
		start_offset = (unsigned long)ftrace_caller;
		end_offset = (unsigned long)ftrace_epilogue;
		op_offset = (unsigned long)ftrace_caller_op_ptr;
	}

	size = end_offset - start_offset;

	/*
	 * Allocate enough size to store the ftrace_caller code,
	 * the iret , as well as the address of the ftrace_ops this
	 * trampoline is used for.
	 */

	/*

	0xffffffff81c01990 <ftrace_caller>:     push   %rbp
	0xffffffff81c01991 <ftrace_caller+1>:   pushq  0x10(%rsp)
	0xffffffff81c01995 <ftrace_caller+5>:   push   %rbp
	0xffffffff81c01996 <ftrace_caller+6>:   mov    %rsp,%rbp
	0xffffffff81c01999 <ftrace_caller+9>:   pushq  0x18(%rsp)
	0xffffffff81c0199d <ftrace_caller+13>:  push   %rbp
	0xffffffff81c0199e <ftrace_caller+14>:  mov    %rsp,%rbp
	0xffffffff81c019a1 <ftrace_caller+17>:  sub    $0xa8,%rsp
	0xffffffff81c019a8 <ftrace_caller+24>:  mov    %rax,0x50(%rsp)
	0xffffffff81c019ad <ftrace_caller+29>:  mov    %rcx,0x58(%rsp)
	0xffffffff81c019b2 <ftrace_caller+34>:  mov    %rdx,0x60(%rsp)
	0xffffffff81c019b7 <ftrace_caller+39>:  mov    %rsi,0x68(%rsp)
	0xffffffff81c019bc <ftrace_caller+44>:  mov    %rdi,0x70(%rsp)
	0xffffffff81c019c1 <ftrace_caller+49>:  mov    %r8,0x48(%rsp)
	0xffffffff81c019c6 <ftrace_caller+54>:  mov    %r9,0x40(%rsp)
	0xffffffff81c019cb <ftrace_caller+59>:  mov    0xc8(%rsp),%rdx
	0xffffffff81c019d3 <ftrace_caller+67>:  mov    %rdx,0x20(%rsp)
	0xffffffff81c019d8 <ftrace_caller+72>:  mov    0xd8(%rsp),%rsi
	0xffffffff81c019e0 <ftrace_caller+80>:  mov    0xd0(%rsp),%rdi
	0xffffffff81c019e8 <ftrace_caller+88>:  mov    %rdi,0x80(%rsp)
	0xffffffff81c019f0 <ftrace_caller+96>:  sub    $0x5,%rdi
	
	0xffffffff81c019f4 <ftrace_caller_op_ptr>:      mov    0xc43c45(%rip),%rdx        # 0xffffffff82845640 <function_trace_op>
	0xffffffff81c019fb <ftrace_caller_op_ptr+7>:    mov    $0x0,%rcx
	
	0xffffffff81c01a02 <ftrace_call>:       callq  0xffffffff81c01a3b <ftrace_stub>
	0xffffffff81c01a07 <ftrace_call+5>:     mov    0x40(%rsp),%r9
	0xffffffff81c01a0c <ftrace_call+10>:    mov    0x48(%rsp),%r8
	0xffffffff81c01a11 <ftrace_call+15>:    mov    0x70(%rsp),%rdi
	0xffffffff81c01a16 <ftrace_call+20>:    mov    0x68(%rsp),%rsi
	0xffffffff81c01a1b <ftrace_call+25>:    mov    0x60(%rsp),%rdx
	0xffffffff81c01a20 <ftrace_call+30>:    mov    0x58(%rsp),%rcx
	0xffffffff81c01a25 <ftrace_call+35>:    mov    0x50(%rsp),%rax
	0xffffffff81c01a2a <ftrace_call+40>:    mov    0x20(%rsp),%rbp
	0xffffffff81c01a2f <ftrace_call+45>:    add    $0xd0,%rsp
	
	0xffffffff81c01a36 <ftrace_epilogue>:   jmpq   0xffffffff81c01a3b <ftrace_stub>
	
	0xffffffff81c01a3b <ftrace_stub>:       retq  





	0xffffffff81c01a40 <ftrace_regs_caller>:        pushfq                                                                     
	0xffffffff81c01a41 <ftrace_regs_caller+1>:      push   %rbp                                                                
	0xffffffff81c01a42 <ftrace_regs_caller+2>:      pushq  0x18(%rsp)
	0xffffffff81c01a46 <ftrace_regs_caller+6>:      push   %rbp                                                                
	0xffffffff81c01a47 <ftrace_regs_caller+7>:      mov    %rsp,%rbp
	0xffffffff81c01a4a <ftrace_regs_caller+10>:     pushq  0x20(%rsp)
	0xffffffff81c01a4e <ftrace_regs_caller+14>:     push   %rbp
	0xffffffff81c01a4f <ftrace_regs_caller+15>:     mov    %rsp,%rbp
	0xffffffff81c01a52 <ftrace_regs_caller+18>:     sub    $0xa8,%rsp
	0xffffffff81c01a59 <ftrace_regs_caller+25>:     mov    %rax,0x50(%rsp)
	0xffffffff81c01a5e <ftrace_regs_caller+30>:     mov    %rcx,0x58(%rsp)
	0xffffffff81c01a63 <ftrace_regs_caller+35>:     mov    %rdx,0x60(%rsp)
	0xffffffff81c01a68 <ftrace_regs_caller+40>:     mov    %rsi,0x68(%rsp)
	0xffffffff81c01a6d <ftrace_regs_caller+45>:     mov    %rdi,0x70(%rsp)
	0xffffffff81c01a72 <ftrace_regs_caller+50>:     mov    %r8,0x48(%rsp)
	0xffffffff81c01a77 <ftrace_regs_caller+55>:     mov    %r9,0x40(%rsp)
	0xffffffff81c01a7c <ftrace_regs_caller+60>:     mov    0xc8(%rsp),%rdx
	0xffffffff81c01a84 <ftrace_regs_caller+68>:     mov    %rdx,0x20(%rsp)
	0xffffffff81c01a89 <ftrace_regs_caller+73>:     mov    0xe0(%rsp),%rsi
	0xffffffff81c01a91 <ftrace_regs_caller+81>:     mov    0xd8(%rsp),%rdi
	0xffffffff81c01a99 <ftrace_regs_caller+89>:     mov    %rdi,0x80(%rsp)
	0xffffffff81c01aa1 <ftrace_regs_caller+97>:     sub    $0x5,%rdi
	
	0xffffffff81c01aa5 <ftrace_regs_caller_op_ptr>: mov    0xc43b94(%rip),%rdx        # 0xffffffff82845640 <function_trace_op>
	0xffffffff81c01aac <ftrace_regs_caller_op_ptr+7>:       mov    %r15,(%rsp)
	0xffffffff81c01ab0 <ftrace_regs_caller_op_ptr+11>:      mov    %r14,0x8(%rsp)
	0xffffffff81c01ab5 <ftrace_regs_caller_op_ptr+16>:      mov    %r13,0x10(%rsp)
	0xffffffff81c01aba <ftrace_regs_caller_op_ptr+21>:      mov    %r12,0x18(%rsp)
	0xffffffff81c01abf <ftrace_regs_caller_op_ptr+26>:      mov    %r11,0x30(%rsp)
	0xffffffff81c01ac4 <ftrace_regs_caller_op_ptr+31>:      mov    %r10,0x38(%rsp)
	0xffffffff81c01ac9 <ftrace_regs_caller_op_ptr+36>:      mov    %rbx,0x28(%rsp)
	0xffffffff81c01ace <ftrace_regs_caller_op_ptr+41>:      mov    0xd0(%rsp),%rcx
	0xffffffff81c01ad6 <ftrace_regs_caller_op_ptr+49>:      mov    %rcx,0x90(%rsp)
	0xffffffff81c01ade <ftrace_regs_caller_op_ptr+57>:      mov    $0x18,%rcx
	0xffffffff81c01ae5 <ftrace_regs_caller_op_ptr+64>:      mov    %rcx,0xa0(%rsp)
	0xffffffff81c01aed <ftrace_regs_caller_op_ptr+72>:      mov    $0x10,%rcx
	0xffffffff81c01af4 <ftrace_regs_caller_op_ptr+79>:      mov    %rcx,0x88(%rsp)
	0xffffffff81c01afc <ftrace_regs_caller_op_ptr+87>:      lea    0xe0(%rsp),%rcx
	0xffffffff81c01b04 <ftrace_regs_caller_op_ptr+95>:      mov    %rcx,0x98(%rsp)
	0xffffffff81c01b0c <ftrace_regs_caller_op_ptr+103>:     lea    (%rsp),%rcx
	
	0xffffffff81c01b10 <ftrace_regs_call>:	callq  0xffffffff81c01a3b <ftrace_stub>
	0xffffffff81c01b15 <ftrace_regs_call+5>:		mov    0x90(%rsp),%rax
	0xffffffff81c01b1d <ftrace_regs_call+13>:		mov    %rax,0xd0(%rsp)
	0xffffffff81c01b25 <ftrace_regs_call+21>:		mov    0x80(%rsp),%rax
	0xffffffff81c01b2d <ftrace_regs_call+29>:		mov    %rax,0xd8(%rsp)
	0xffffffff81c01b35 <ftrace_regs_call+37>:		mov    (%rsp),%r15
	0xffffffff81c01b39 <ftrace_regs_call+41>:		mov    0x8(%rsp),%r14
	0xffffffff81c01b3e <ftrace_regs_call+46>:		mov    0x10(%rsp),%r13
	0xffffffff81c01b43 <ftrace_regs_call+51>:		mov    0x18(%rsp),%r12
	0xffffffff81c01b48 <ftrace_regs_call+56>:		mov    0x38(%rsp),%r10
	0xffffffff81c01b4d <ftrace_regs_call+61>:		mov    0x28(%rsp),%rbx
	0xffffffff81c01b52 <ftrace_regs_call+66>:		mov    0x40(%rsp),%r9
	0xffffffff81c01b57 <ftrace_regs_call+71>:		mov    0x48(%rsp),%r8
	0xffffffff81c01b5c <ftrace_regs_call+76>:		mov    0x70(%rsp),%rdi
	0xffffffff81c01b61 <ftrace_regs_call+81>:		mov    0x68(%rsp),%rsi
	0xffffffff81c01b66 <ftrace_regs_call+86>:		mov    0x60(%rsp),%rdx
	0xffffffff81c01b6b <ftrace_regs_call+91>:		mov    0x58(%rsp),%rcx
	0xffffffff81c01b70 <ftrace_regs_call+96>:		mov    0x50(%rsp),%rax
	0xffffffff81c01b75 <ftrace_regs_call+101>:		mov    0x20(%rsp),%rbp
	0xffffffff81c01b7a <ftrace_regs_call+106>:		add    $0xd0,%rsp
	0xffffffff81c01b81 <ftrace_regs_call+113>:		popfq  
	
	0xffffffff81c01b82 <ftrace_regs_caller_end>:	jmpq   0xffffffff81c01a36 <ftrace_epilogue>


	trampoline 的结构（最终）
	+--------+	  ftrace_caller(start_offset)
	|		 |
	|		 |	  ftrace_caller_op_ptr(op_offset)
	|		 |
	|  size  |	  ftrace_call(call_offset)
	|		 |
	+--------+	  ftrace_caller_end(end_offset)
	|RET_SIZE|	  ftrace_stub	 <--ip
	+--------+
	| void * | ---> ops
	+--------+



	*/
	trampoline = alloc_tramp(size + RET_SIZE + sizeof(void *));
	if (!trampoline)
		return 0;

	*tramp_size = size + RET_SIZE + sizeof(void *);
	npages = DIV_ROUND_UP(*tramp_size, PAGE_SIZE);

	/* Copy ftrace_caller onto the trampoline memory */
	/* start_offset, start_offset + size ===拷贝到===> trampoline */
	ret = probe_kernel_read(trampoline, (void *)start_offset, size);
	if (WARN_ON(ret < 0))
		goto fail;

	ip = trampoline + size;

	/* The trampoline ends with ret(q) */
	retq = (unsigned long)ftrace_stub;
	/*
	 * ftrace_stub 函数的第一个字节 放到*ip中， 其实就是一个ret 指令
	 * 0xffffffff81c01a3b <ftrace_stub>:		retq ==> 1个字节
	 * 0xffffffff81c01a3c <ftrace_stub+1>:     nopl   0x0(%rax)
	*/
	ret = probe_kernel_read(ip, (void *)retq, RET_SIZE);
	if (WARN_ON(ret < 0))
		goto fail;

	/*
	 * The address of the ftrace_ops that is used for this trampoline
	 * is stored at the end of the trampoline. This will be used to
	 * load the third parameter for the callback. Basically, that
	 * location at the end of the trampoline takes the place of
	 * the global function_trace_op variable.
	 */

	ptr = (unsigned long *)(trampoline + size + RET_SIZE);
	*ptr = (unsigned long)ops;

	op_offset -= start_offset;
	memcpy(&op_ptr, trampoline + op_offset, OP_REF_SIZE);

	/* Are we pointing to the reference? */
	/*把 trampoline*/
	if (WARN_ON(memcmp(op_ptr.op, op_ref, 3) != 0))
		goto fail;

	/* Load the contents of ptr into the callback parameter */
	offset = (unsigned long)ptr;
	offset -= (unsigned long)trampoline + op_offset + OP_REF_SIZE;

	op_ptr.offset = offset;
	/*
	 * 因为trampoline 是对每个ops 一个的,我们这里拷贝的trampoline 只是一个模板
	 * 所以要修改成对应的ops 的trampoline
	 * 
	 * 这里最重要的就是这个op_ptr,
	 * op_ptr 对应的是 movq function_trace_op(%rip), %rdx
	 * 0x48 0x8b 0x15 <offset-to-ftrace_trace_op (4 bytes)>
	 * 由于ftrace_trace_op 的指针就在trampoline的最下面, 所以我们希望把这个指针给rdx,
	 * 然后调用 ftrace_stub函数
	/* put in the new offset to the ftrace_ops */
	memcpy(trampoline + op_offset, &op_ptr, OP_REF_SIZE);

	/* ALLOC_TRAMP flags lets us know we created it */
	ops->flags |= FTRACE_OPS_FL_ALLOC_TRAMP;

	set_vm_flush_reset_perms(trampoline);

	/*
	 * Module allocation needs to be completed by making the page
	 * executable. The page is still writable, which is a security hazard,
	 * but anyhow ftrace breaks W^X completely.
	 */
	set_memory_x((unsigned long)trampoline, npages);
	return (unsigned long)trampoline;
fail:
	tramp_free(trampoline);
	return 0;
}

static unsigned long calc_trampoline_call_offset(bool save_regs)
{
	unsigned long start_offset;
	unsigned long call_offset;

	if (save_regs) {
		start_offset = (unsigned long)ftrace_regs_caller;
		call_offset = (unsigned long)ftrace_regs_call;
	} else {
		start_offset = (unsigned long)ftrace_caller;
		call_offset = (unsigned long)ftrace_call;
	}

	return call_offset - start_offset;
}

void arch_ftrace_update_trampoline(struct ftrace_ops *ops)
{
	ftrace_func_t func;
	unsigned char *new;
	unsigned long offset;
	unsigned long ip;
	unsigned int size;
	int ret, npages;

	if (ops->trampoline) {
		/*
		 * The ftrace_ops caller may set up its own trampoline.
		 * In such a case, this code must not modify it.
		 */
		if (!(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
			return;
		npages = PAGE_ALIGN(ops->trampoline_size) >> PAGE_SHIFT;
		set_memory_rw(ops->trampoline, npages);
	} else {
		/*针对这个ops创建trampoilne*/
		ops->trampoline = create_trampoline(ops, &size);
		if (!ops->trampoline)
			return;
		ops->trampoline_size = size;
		npages = PAGE_ALIGN(size) >> PAGE_SHIFT;
	}

	offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
	/*这个ip实际上就是 trampoline中 call ftrace_stub的地址*/
	ip = ops->trampoline + offset; 

	func = ftrace_ops_get_func(ops);

	ftrace_update_func_call = (unsigned long)func;

	/* Do a safe modify in case the trampoline is executing */
	/*生成call func 指令*/
	new = ftrace_call_replace(ip, (unsigned long)func);
	/*
	 * 把这个指令放到ip对应的内存中
	 * 这样call ftrace_stub 就编程了 call ops->func
	 */
	ret = update_ftrace_func(ip, new);
	set_memory_ro(ops->trampoline, npages);

	/* The update should never fail */
	WARN_ON(ret);
}

/* Return the address of the function the trampoline calls */
static void *addr_from_call(void *ptr)
{
	union ftrace_code_union calc;
	int ret;

	ret = probe_kernel_read(&calc, ptr, MCOUNT_INSN_SIZE);
	if (WARN_ON_ONCE(ret < 0))
		return NULL;

	/* Make sure this is a call */
	if (WARN_ON_ONCE(calc.op != 0xe8)) {
		pr_warn("Expected e8, got %x\n", calc.op);
		return NULL;
	}

	return ptr + MCOUNT_INSN_SIZE + calc.offset;
}

void prepare_ftrace_return(unsigned long self_addr, unsigned long *parent,
			   unsigned long frame_pointer);

/*
 * If the ops->trampoline was not allocated, then it probably
 * has a static trampoline func, or is the ftrace caller itself.
 */
static void *static_tramp_func(struct ftrace_ops *ops, struct dyn_ftrace *rec)
{
	unsigned long offset;
	bool save_regs = rec->flags & FTRACE_FL_REGS_EN;
	void *ptr;

	if (ops && ops->trampoline) {
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		/*
		 * We only know about function graph tracer setting as static
		 * trampoline.
		 */
		if (ops->trampoline == FTRACE_GRAPH_ADDR)
			return (void *)prepare_ftrace_return;
#endif
		return NULL;
	}

	offset = calc_trampoline_call_offset(save_regs);

	if (save_regs)
		ptr = (void *)FTRACE_REGS_ADDR + offset;
	else
		ptr = (void *)FTRACE_ADDR + offset;

	return addr_from_call(ptr);
}

void *arch_ftrace_trampoline_func(struct ftrace_ops *ops, struct dyn_ftrace *rec)
{
	unsigned long offset;

	/* If we didn't allocate this trampoline, consider it static */
	if (!ops || !(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return static_tramp_func(ops, rec);

	offset = calc_trampoline_call_offset(ops->flags & FTRACE_OPS_FL_SAVE_REGS);
	return addr_from_call((void *)ops->trampoline + offset);
}

void arch_ftrace_trampoline_free(struct ftrace_ops *ops)
{
	if (!ops || !(ops->flags & FTRACE_OPS_FL_ALLOC_TRAMP))
		return;

	tramp_free((void *)ops->trampoline);
	ops->trampoline = 0;
}

#endif /* CONFIG_X86_64 */
#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER

#ifdef CONFIG_DYNAMIC_FTRACE
extern void ftrace_graph_call(void);

static unsigned char *ftrace_jmp_replace(unsigned long ip, unsigned long addr)
{
	return ftrace_text_replace(0xe9, ip, addr);
}

/*  *ip  = jmp func */
static int ftrace_mod_jmp(unsigned long ip, void *func)
{
	unsigned char *new;

	ftrace_update_func_call = 0UL;
	new = ftrace_jmp_replace(ip, (unsigned long)func);

	return update_ftrace_func(ip, new);
}

/*
 * ftrace_graph_call 是ftrace_caller函数中的一个指令位置
 * 并不是一个函数, 见ftrace_64.S
 */
int ftrace_enable_ftrace_graph_caller(void)
{

	unsigned long ip = (unsigned long)(&ftrace_graph_call);

	return ftrace_mod_jmp(ip, &ftrace_graph_caller);
	/*ftrace_graph_call 替换成 jmp ftrace_graph_caller*/
}


/*
 * ftrace_graph_call 是ftrace_caller函数中的一个指令位置
 * 并不是一个函数, 见ftrace_64.S
 */
int ftrace_disable_ftrace_graph_caller(void)
{
	unsigned long ip = (unsigned long)(&ftrace_graph_call);

	/*替换为 jmp ftrace_stub*/
	return ftrace_mod_jmp(ip, &ftrace_stub);
}

#endif /* !CONFIG_DYNAMIC_FTRACE */

/*
 * Hook the return address and push it in the stack of return addrs
 * in current thread info.
 */
 /*
 B()
 {
		A() {
			ftrace_caller ===>@self_addr 用来记录该函数的
			instruction_rdi
		}
		instru ====>@parent
 }
 
@parent 为栈中, 本call指令返回后的下一条指令
@self_addr 当前被trace 的函数的首地址
ftrace_graph_caller 中有一条指令为: (save_mcount_regs宏产生的)

sub    $0x5,%rdi  rdi 本来指向返回地址 , 就是上图中instruction_rdi

然后减去5 就是function 开头的地址, 经过替换之后,就是A的

ftrace_graph_call中会调用
	prepare_ftrace_return // 修改返回地址为 ret_to_handler
		function_graph_enter
			ftrace_graph_entry_test
				trace_graph_entry

	
*/
void prepare_ftrace_return(unsigned long self_addr, unsigned long *parent,
			   unsigned long frame_pointer)
{
	unsigned long old;
	int faulted;
	unsigned long return_hooker = (unsigned long)
				&return_to_handler;

	/*
	 * When resuming from suspend-to-ram, this function can be indirectly
	 * called from early CPU startup code while the CPU is in real mode,
	 * which would fail miserably.  Make sure the stack pointer is a
	 * virtual address.
	 *
	 * This check isn't as accurate as virt_addr_valid(), but it should be
	 * good enough for this purpose, and it's fast.
	 */
	if (unlikely((long)__builtin_frame_address(0) >= 0))
		return;

	if (unlikely(ftrace_graph_is_dead()))
		return;

	if (unlikely(atomic_read(&current->tracing_graph_pause)))
		return;

	/*
	 * Protect against fault, even if it shouldn't
	 * happen. This tool is too much intrusive to
	 * ignore such a protection.
	 */
	asm volatile(
		/*old = parent*/
		"1: " _ASM_MOV " (%[parent]), %[old]\n"
		/* parent = return_hooker */
		/*保证A函数返回之后 能够进入return hooker*/
		"2: " _ASM_MOV " %[return_hooker], (%[parent])\n"
		"   movl $0, %[faulted]\n"
		"3:\n"

		".section .fixup, \"ax\"\n"
		"4: movl $1, %[faulted]\n"
		"   jmp 3b\n"
		".previous\n"

		_ASM_EXTABLE(1b, 4b)
		_ASM_EXTABLE(2b, 4b)

		: [old] "=&r" (old), [faulted] "=r" (faulted)
		: [parent] "r" (parent), [return_hooker] "r" (return_hooker)
		: "memory"
	);

	if (unlikely(faulted)) {
		ftrace_graph_stop();
		WARN_ON(1);
		return;
	}

	/*这里用来几乎graph trace */
	/*
	 * @self_addr 为当前函数
	 * @parent 为父亲函数的返回地址
	 */
	if (function_graph_enter(old, self_addr, frame_pointer, parent))
		*parent = old;
}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */
