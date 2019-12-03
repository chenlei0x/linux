/* SPDX-License-Identifier: GPL-2.0 */
/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/wait.h>
#include <linux/compiler.h>

struct kmem_cache;

typedef void * (mempool_alloc_t)(gfp_t gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

/*
 * 内核中经常需要申请大量的相同类型的较小数据结构的内存，例如skb、urb
 * 这样容易出现内存碎片
 * 使用SLAB预先分配一片空间专门用来给这类数据结构使用，能够提高申请和回收速度，减少内存碎片
 * SLAB适合于大量的、细小的数据结构的内存申请的情况
 *
 * 内存池，大多用于块设备，如文件系统
 * 在处理大量的数据时，可能内核可用的内存不足，使用内存池预先申请一块内存
 * 这样使用内存池api mempool_alloc，首先尝试alloc_fn ，如果失败就从内存池中获取预分配的内存，能够保证
 * mempool_alloc一定申请成功，不会陷入睡眠（当然预分配的内存没有了，也会睡眠）。
 */
typedef struct mempool_s {
	spinlock_t lock;
	int min_nr;		/* nr of elements at *elements */
	int curr_nr;		/* Current nr of elements at *elements */
	void **elements;

	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
} mempool_t;

extern mempool_t *mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data);
extern mempool_t *mempool_create_node(int min_nr, mempool_alloc_t *alloc_fn,
			mempool_free_t *free_fn, void *pool_data,
			gfp_t gfp_mask, int nid);

extern int mempool_resize(mempool_t *pool, int new_min_nr);
extern void mempool_destroy(mempool_t *pool);
extern void *mempool_alloc(mempool_t *pool, gfp_t gfp_mask) __malloc;
extern void mempool_free(void *element, mempool_t *pool);

/*
 * A mempool_alloc_t and mempool_free_t that get the memory from
 * a slab cache that is passed in through pool_data.
 * Note: the slab cache may not have a ctor function.
 */
void *mempool_alloc_slab(gfp_t gfp_mask, void *pool_data);
void mempool_free_slab(void *element, void *pool_data);
static inline mempool_t *
mempool_create_slab_pool(int min_nr, struct kmem_cache *kc)
{
	return mempool_create(min_nr, mempool_alloc_slab, mempool_free_slab,
			      (void *) kc);
}

/*
 * a mempool_alloc_t and a mempool_free_t to kmalloc and kfree the
 * amount of memory specified by pool_data
 */
void *mempool_kmalloc(gfp_t gfp_mask, void *pool_data);
void mempool_kfree(void *element, void *pool_data);
static inline mempool_t *mempool_create_kmalloc_pool(int min_nr, size_t size)
{
	return mempool_create(min_nr, mempool_kmalloc, mempool_kfree,
			      (void *) size);
}

/*
 * A mempool_alloc_t and mempool_free_t for a simple page allocator that
 * allocates pages of the order specified by pool_data
 */
void *mempool_alloc_pages(gfp_t gfp_mask, void *pool_data);
void mempool_free_pages(void *element, void *pool_data);
static inline mempool_t *mempool_create_page_pool(int min_nr, int order)
{
	return mempool_create(min_nr, mempool_alloc_pages, mempool_free_pages,
			      (void *)(long)order);
}

#endif /* _LINUX_MEMPOOL_H */
