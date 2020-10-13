/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RQ_QOS_H
#define RQ_QOS_H

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/atomic.h>
#include <linux/wait.h>

#include "blk-mq-debugfs.h"

struct blk_mq_debugfs_attr;

enum rq_qos_id {
	RQ_QOS_WBT,
	RQ_QOS_LATENCY,
	RQ_QOS_COST,
};

struct rq_wait {
	wait_queue_head_t wait;
	atomic_t inflight;
};

struct rq_qos {
	struct rq_qos_ops *ops;
	struct request_queue *q;
	enum rq_qos_id id;
	struct rq_qos *next;
#ifdef CONFIG_BLK_DEBUG_FS
	struct dentry *debugfs_dir;
#endif
};


/*
3个qos
ioc_rqos_ops
blkcg_iolatency_ops
wbt_rqos_ops
*/
struct rq_qos_ops {
	/*
		blk_mq_make_request
			rq_qos_throttle
				__rq_qos_throttle
					每个qos如果需要需要对当前io进行qos处理,则会直接睡眠
	*/
	void (*throttle)(struct rq_qos *, struct bio *);
	/*
	blk_mq_make_request
		rq_qos_track 产生了rq

	*/
	void (*track)(struct rq_qos *, struct request *, struct bio *);

	/*bio 可以合并到rq中
	bio_attempt_front_merge
		bio_attempt_back_merge
	*/
	void (*merge)(struct rq_qos *, struct request *, struct bio *);
	/*
	 * blk_mq_start_request 驱动层开始处理这个req
	 */
	void (*issue)(struct rq_qos *, struct request *);
	/*__blk_mq_requeue_request*/
	void (*requeue)(struct rq_qos *, struct request *);
	/*__blk_mq_end_request 会调用*/
	void (*done)(struct rq_qos *, struct request *);

	/* bio_endio会调用他*/
	void (*done_bio)(struct rq_qos *, struct bio *);
	/*blk_mq_get_request 返回失败*/
	void (*cleanup)(struct rq_qos *, struct bio *);
	/*blk_set_queue_depth 会调用*/
	void (*queue_depth_changed)(struct rq_qos *);
	/*blk_cleanup_queue 调用， 关闭queue*/
	void (*exit)(struct rq_qos *);
	const struct blk_mq_debugfs_attr *debugfs_attrs;
};

struct rq_depth {
	/*rq_depth_calc_max_depth*/
	unsigned int max_depth; /*UINT_MAX*/

	/*rq_depth_scale_down rq_depth_scale_up 这几个函数会影响该值
	初始化为0, > 0 表示latency 增大, < 0 表示可以增大depth*/
	int scale_step; 

	/*rq_depth_calc_max_depth 计算得到, 表示depth 已经放大到极限了*/
	bool scaled_max;

	/*wbt_queue_depth_changed 会进行更改*/
	unsigned int queue_depth; /*初始化为blkg->q->nr_requests*/
	unsigned int default_depth; /*初始化为 RWB_DEF_DEPTH = 16*/
};

static inline struct rq_qos *rq_qos_id(struct request_queue *q,
				       enum rq_qos_id id)
{
	struct rq_qos *rqos;
	for (rqos = q->rq_qos; rqos; rqos = rqos->next) {
		if (rqos->id == id)
			break;
	}
	return rqos;
}

static inline struct rq_qos *wbt_rq_qos(struct request_queue *q)
{
	return rq_qos_id(q, RQ_QOS_WBT);
}

static inline struct rq_qos *blkcg_rq_qos(struct request_queue *q)
{
	return rq_qos_id(q, RQ_QOS_LATENCY);
}

static inline const char *rq_qos_id_to_name(enum rq_qos_id id)
{
	switch (id) {
	case RQ_QOS_WBT:
		return "wbt";
	case RQ_QOS_LATENCY:
		return "latency";
	case RQ_QOS_COST:
		return "cost";
	}
	return "unknown";
}

static inline void rq_wait_init(struct rq_wait *rq_wait)
{
	atomic_set(&rq_wait->inflight, 0);
	init_waitqueue_head(&rq_wait->wait);
}

/*头插*/
static inline void rq_qos_add(struct request_queue *q, struct rq_qos *rqos)
{
	rqos->next = q->rq_qos;
	q->rq_qos = rqos;

	if (rqos->ops->debugfs_attrs)
		blk_mq_debugfs_register_rqos(rqos);
}

static inline void rq_qos_del(struct request_queue *q, struct rq_qos *rqos)
{
	struct rq_qos **cur;

	for (cur = &q->rq_qos; *cur; cur = &(*cur)->next) {
		if (*cur == rqos) {
			*cur = rqos->next;
			break;
		}
	}

	blk_mq_debugfs_unregister_rqos(rqos);
}

typedef bool (acquire_inflight_cb_t)(struct rq_wait *rqw, void *private_data);
typedef void (cleanup_cb_t)(struct rq_wait *rqw, void *private_data);

void rq_qos_wait(struct rq_wait *rqw, void *private_data,
		 acquire_inflight_cb_t *acquire_inflight_cb,
		 cleanup_cb_t *cleanup_cb);
bool rq_wait_inc_below(struct rq_wait *rq_wait, unsigned int limit);
bool rq_depth_scale_up(struct rq_depth *rqd);
bool rq_depth_scale_down(struct rq_depth *rqd, bool hard_throttle);
bool rq_depth_calc_max_depth(struct rq_depth *rqd);

void __rq_qos_cleanup(struct rq_qos *rqos, struct bio *bio);
void __rq_qos_done(struct rq_qos *rqos, struct request *rq);
void __rq_qos_issue(struct rq_qos *rqos, struct request *rq);
void __rq_qos_requeue(struct rq_qos *rqos, struct request *rq);
void __rq_qos_throttle(struct rq_qos *rqos, struct bio *bio);
void __rq_qos_track(struct rq_qos *rqos, struct request *rq, struct bio *bio);
void __rq_qos_merge(struct rq_qos *rqos, struct request *rq, struct bio *bio);
void __rq_qos_done_bio(struct rq_qos *rqos, struct bio *bio);
void __rq_qos_queue_depth_changed(struct rq_qos *rqos);

static inline void rq_qos_cleanup(struct request_queue *q, struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_cleanup(q->rq_qos, bio);
}

static inline void rq_qos_done(struct request_queue *q, struct request *rq)
{
	if (q->rq_qos)
		__rq_qos_done(q->rq_qos, rq);
}

static inline void rq_qos_issue(struct request_queue *q, struct request *rq)
{
	if (q->rq_qos)
		__rq_qos_issue(q->rq_qos, rq);
}

static inline void rq_qos_requeue(struct request_queue *q, struct request *rq)
{
	if (q->rq_qos)
		__rq_qos_requeue(q->rq_qos, rq);
}

static inline void rq_qos_done_bio(struct request_queue *q, struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_done_bio(q->rq_qos, bio);
}

static inline void rq_qos_throttle(struct request_queue *q, struct bio *bio)
{
	/*
	 * BIO_TRACKED lets controllers know that a bio went through the
	 * normal rq_qos path.
	 */
	bio_set_flag(bio, BIO_TRACKED);
	if (q->rq_qos)
		__rq_qos_throttle(q->rq_qos, bio);
}

static inline void rq_qos_track(struct request_queue *q, struct request *rq,
				struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_track(q->rq_qos, rq, bio);
}

static inline void rq_qos_merge(struct request_queue *q, struct request *rq,
				struct bio *bio)
{
	if (q->rq_qos)
		__rq_qos_merge(q->rq_qos, rq, bio);
}

static inline void rq_qos_queue_depth_changed(struct request_queue *q)
{
	if (q->rq_qos)
		__rq_qos_queue_depth_changed(q->rq_qos);
}

void rq_qos_exit(struct request_queue *);

#endif
