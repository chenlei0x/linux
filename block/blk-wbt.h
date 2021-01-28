/* SPDX-License-Identifier: GPL-2.0 */
#ifndef WB_THROTTLE_H
#define WB_THROTTLE_H

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/ktime.h>

#include "blk-stat.h"
#include "blk-rq-qos.h"

enum wbt_flags {
	WBT_TRACKED		= 1,	/* write, tracked for throttling */
	WBT_READ		= 2,	/* read */
	WBT_KSWAPD		= 4,	/* write, from kswapd */
	WBT_DISCARD		= 8,	/* discard */

	WBT_NR_BITS		= 4,	/* number of bits */
};

enum {
	WBT_RWQ_BG		= 0,
	WBT_RWQ_KSWAPD,
	WBT_RWQ_DISCARD,
	WBT_NUM_RWQ,
};

/*
 * Enable states. Either off, or on by default (done at init time),
 * or on through manual setup in sysfs.
 */
enum {
	WBT_STATE_ON_DEFAULT	= 1,
	WBT_STATE_ON_MANUAL	= 2,
};

/*每个q 对应一个*/
struct rq_wb {
	/*
	 * Settings that govern how we throttle
	 *
	 * 这两个值由 calc_wb_limits 计算得来
	 */
	 /*对于超时或者超限脏页数量的io*/
	unsigned int wb_background;		/* background writeback */
	/*
	 * 没有REQ_BACKGROUND标记的回写的io, 且不是sync的比如
	 * 	unsigned for_reclaim:1;		用于内存回收	
	 */
	unsigned int wb_normal;			/* normal writeback */

	short enable_state;			/* WBT_STATE_* */

	/*
	 * Number of consecutive periods where we don't have enough
	 * information to make a firm scale up/down decision.
	 */
	unsigned int unknown_cnt;

	/*RWB_WINDOW_NSEC*/
	u64 win_nsec;				/* default window size */
	u64 cur_win_nsec;			/* current window size */

	struct blk_stat_callback *cb; /*wb_timer_fn*/

	/*
	 * blk_mq_start_request
	 * 		wbt_issue
	 * 这个字段用来记录sync IO 开始的时间
	 * 在IO结束时,置为空
	 * 作用是为了防止某个io 在时间窗口内开始,但是在时间窗口结束时还没结束
	 * 这种IO通过 结束 - 开始的方式 统计不到,因为没有结束
	 * 但是如果这个IO存在,且长时间没有完成,就说明已经很久了
	 * 这时候我们需要上报已经有超时现象了
	 */
	u64 sync_issue;
	void *sync_cookie; /*= rq*/

	unsigned int wc;

	/*最近一次 非throttle 的io 下发的时刻*/
	unsigned long last_issue;		/* last non-throttled issue */
	/*最近一次 非throttle 的io 完成的时刻*/
	unsigned long last_comp;		/* last non-throttled comp */
	unsigned long min_lat_nsec;
	struct rq_qos rqos; /*通用 obj*/
	struct rq_wait rq_wait[WBT_NUM_RWQ];
	struct rq_depth rq_depth;
};

static inline struct rq_wb *RQWB(struct rq_qos *rqos)
{
	return container_of(rqos, struct rq_wb, rqos);
}

static inline unsigned int wbt_inflight(struct rq_wb *rwb)
{
	unsigned int i, ret = 0;

	for (i = 0; i < WBT_NUM_RWQ; i++)
		ret += atomic_read(&rwb->rq_wait[i].inflight);

	return ret;
}


#ifdef CONFIG_BLK_WBT

int wbt_init(struct request_queue *);
void wbt_update_limits(struct request_queue *);
void wbt_disable_default(struct request_queue *);
void wbt_enable_default(struct request_queue *);

u64 wbt_get_min_lat(struct request_queue *q);
void wbt_set_min_lat(struct request_queue *q, u64 val);

void wbt_set_write_cache(struct request_queue *, bool);

u64 wbt_default_latency_nsec(struct request_queue *);

#else

static inline void wbt_track(struct request *rq, enum wbt_flags flags)
{
}
static inline int wbt_init(struct request_queue *q)
{
	return -EINVAL;
}
static inline void wbt_update_limits(struct request_queue *q)
{
}
static inline void wbt_disable_default(struct request_queue *q)
{
}
static inline void wbt_enable_default(struct request_queue *q)
{
}
static inline void wbt_set_write_cache(struct request_queue *q, bool wc)
{
}
static inline u64 wbt_get_min_lat(struct request_queue *q)
{
	return 0;
}
static inline void wbt_set_min_lat(struct request_queue *q, u64 val)
{
}
static inline u64 wbt_default_latency_nsec(struct request_queue *q)
{
	return 0;
}

#endif /* CONFIG_BLK_WBT */

#endif
