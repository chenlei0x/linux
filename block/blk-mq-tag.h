/* SPDX-License-Identifier: GPL-2.0 */
#ifndef INT_BLK_MQ_TAG_H
#define INT_BLK_MQ_TAG_H

#include "blk-mq.h"

/*
 * Tag address space map.
 *
 * 对应一个hw queue， 每个hw queue都有自己的rq 队列，和bitmap
 */
struct blk_mq_tags {
	/* depth = tags->nr_tags - tags->nr_reserved_tags;*/
	unsigned int nr_tags;/*blk_mq_tag_set->queue_depth*/
	unsigned int nr_reserved_tags;/*blk_mq_tag_set->reserved_tags*/

	atomic_t active_queues;

	/*以下两个bitmap用来描述 static_rqs中的使用情况*/
	struct sbitmap_queue bitmap_tags;/*长度为depth*/
	struct sbitmap_queue breserved_tags; /*长度为nr_reserved_tags*/

	/*用来记录正在使用的rqs
	  初始化该map：
	  	blk_mq_alloc_rq_map
	  后续使用：
		blk_mq_get_driver_tag
			rq->tag = blk_mq_get_tag(&data);
			data.hctx->tags->rqs[rq->tag] = rq;

	  释放：
	  	blk_mq_free_request
	*/
	struct request **rqs; /*长度为nr_tags*/
	/*
	  blk_mq_alloc_rq_map 初始化
	  bitmap_tags 中描述的就是该数组中的所有req
	 */
	struct request **static_rqs; /*长度为nr_tags*/
	struct list_head page_list;
};


extern struct blk_mq_tags *blk_mq_init_tags(unsigned int nr_tags, unsigned int reserved_tags, int node, int alloc_policy);
extern void blk_mq_free_tags(struct blk_mq_tags *tags);

extern unsigned int blk_mq_get_tag(struct blk_mq_alloc_data *data);
extern void blk_mq_put_tag(struct blk_mq_hw_ctx *hctx, struct blk_mq_tags *tags,
			   struct blk_mq_ctx *ctx, unsigned int tag);
extern int blk_mq_tag_update_depth(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_tags **tags,
					unsigned int depth, bool can_grow);
extern void blk_mq_tag_wakeup_all(struct blk_mq_tags *tags, bool);
void blk_mq_queue_tag_busy_iter(struct request_queue *q, busy_iter_fn *fn,
		void *priv);

static inline struct sbq_wait_state *bt_wait_ptr(struct sbitmap_queue *bt,
						 struct blk_mq_hw_ctx *hctx)
{
	if (!hctx)
		return &bt->ws[0];
	return sbq_wait_ptr(bt, &hctx->wait_index);
}

enum {
	BLK_MQ_TAG_FAIL		= -1U,
	BLK_MQ_TAG_MIN		= 1,
	BLK_MQ_TAG_MAX		= BLK_MQ_TAG_FAIL - 1,
};

extern bool __blk_mq_tag_busy(struct blk_mq_hw_ctx *);
extern void __blk_mq_tag_idle(struct blk_mq_hw_ctx *);

static inline bool blk_mq_tag_busy(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return false;

	return __blk_mq_tag_busy(hctx);
}

static inline void blk_mq_tag_idle(struct blk_mq_hw_ctx *hctx)
{
	if (!(hctx->flags & BLK_MQ_F_TAG_SHARED))
		return;

	__blk_mq_tag_idle(hctx);
}

/*
 * This helper should only be used for flush request to share tag
 * with the request cloned from, and both the two requests can't be
 * in flight at the same time. The caller has to make sure the tag
 * can't be freed.
 */
static inline void blk_mq_tag_set_rq(struct blk_mq_hw_ctx *hctx,
		unsigned int tag, struct request *rq)
{
	hctx->tags->rqs[tag] = rq;
}

static inline bool blk_mq_tag_is_reserved(struct blk_mq_tags *tags,
					  unsigned int tag)
{
	return tag < tags->nr_reserved_tags;
}

#endif
