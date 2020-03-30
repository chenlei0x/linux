/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGE_64_H
#define _ASM_X86_PAGE_64_H

#include <asm/page_64_types.h>

#ifndef __ASSEMBLY__
#include <asm/alternative.h>

/* duplicated to the one in bootmem.h */
extern unsigned long max_pfn;
extern unsigned long phys_base;

static inline unsigned long __phys_addr_nodebug(unsigned long x)
{
	unsigned long y = x - __START_KERNEL_map;

	/* use the carry flag to determine if x was < __START_KERNEL_map */
	/*
	 * x 可能会来自于两个地方,第一个 x > __START_KERNEL_map
	 * 第二个 x > PAGE_OFFSET  且 < __START_KERNEL_map
	 * 
	  * 只有当x > __START_KERNEL_map时, x > y 才会成立
	 * __START_KERNEL_map ~ 0xffffffff ffffffff 是内核用来线性映射内存的 phys_base ~ phsy_base + 2G - 1, 通常 phys_base = 0
	 * 所以返回的是物理地址的开始即 phys_base

	 * 当 x < y 时, PAGE_OFFSET < x < __START_KERNEL_map
	 * 这时候, return = y + __START_KERNEL_map - PAGE_OFFSET = x + PAGE_OFFSET
	 * PAGE_OFFSET ~ PAGE_OFFSET + 64TB 映射物理内存的 0 ~ 64TB
	 *
	 * 当phys_base = 0时, __START_KERNEL_map 和 PAGE_OFFSET 都映射着物理地址 从0 开始的部分,只是长度不同
	 * 但是内核可以载入到任意物理地址上, 只要他的让他的__START_KERNEL_map 映射到载入到的地址上就可以了
	 */
	x = y + ((x > y) ? phys_base : (__START_KERNEL_map - PAGE_OFFSET));

	return x;
}

#ifdef CONFIG_DEBUG_VIRTUAL
extern unsigned long __phys_addr(unsigned long);
extern unsigned long __phys_addr_symbol(unsigned long);
#else
#define __phys_addr(x)		__phys_addr_nodebug(x)
#define __phys_addr_symbol(x) \
	((unsigned long)(x) - __START_KERNEL_map + phys_base)
#endif

#define __phys_reloc_hide(x)	(x)

#ifdef CONFIG_FLATMEM
#define pfn_valid(pfn)          ((pfn) < max_pfn)
#endif

void clear_page_orig(void *page);
void clear_page_rep(void *page);
void clear_page_erms(void *page);

static inline void clear_page(void *page)
{
	alternative_call_2(clear_page_orig,
			   clear_page_rep, X86_FEATURE_REP_GOOD,
			   clear_page_erms, X86_FEATURE_ERMS,
			   "=D" (page),
			   "0" (page)
			   : "memory", "rax", "rcx");
}

void copy_page(void *to, void *from);

#endif	/* !__ASSEMBLY__ */

#ifdef CONFIG_X86_VSYSCALL_EMULATION
# define __HAVE_ARCH_GATE_AREA 1
#endif

#endif /* _ASM_X86_PAGE_64_H */
