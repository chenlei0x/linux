/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ELEVATOR_H
#define _LINUX_ELEVATOR_H

#include <linux/percpu.h>
#include <linux/hashtable.h>

#ifdef CONFIG_BLOCK

struct io_cq;
struct elevator_type;
#ifdef CONFIG_BLK_DEBUG_FS
struct blk_mq_debugfs_attr;
#endif

/*
 * Return values from elevator merger
 */
enum elv_merge {
	ELEVATOR_NO_MERGE	= 0,
	ELEVATOR_FRONT_MERGE	= 1,
	ELEVATOR_BACK_MERGE	= 2,
	ELEVATOR_DISCARD_MERGE	= 3,
};

typedef enum elv_merge (elevator_merge_fn) (struct request_queue *, struct request **,
				 struct bio *);

typedef void (elevator_merge_req_fn) (struct request_queue *, struct request *, struct request *);

typedef void (elevator_merged_fn) (struct request_queue *, struct request *, enum elv_merge);

typedef int (elevator_allow_bio_merge_fn) (struct request_queue *,
					   struct request *, struct bio *);

typedef int (elevator_allow_rq_merge_fn) (struct request_queue *,
					  struct request *, struct request *);

typedef void (elevator_bio_merged_fn) (struct request_queue *,
						struct request *, struct bio *);

typedef int (elevator_dispatch_fn) (struct request_queue *, int);

typedef void (elevator_add_req_fn) (struct request_queue *, struct request *);
typedef struct request *(elevator_request_list_fn) (struct request_queue *, struct request *);
typedef void (elevator_completed_req_fn) (struct request_queue *, struct request *);
typedef int (elevator_may_queue_fn) (struct request_queue *, unsigned int);

typedef void (elevator_init_icq_fn) (struct io_cq *);
typedef void (elevator_exit_icq_fn) (struct io_cq *);
typedef int (elevator_set_req_fn) (struct request_queue *, struct request *,
				   struct bio *, gfp_t);
typedef void (elevator_put_req_fn) (struct request *);
typedef void (elevator_activate_req_fn) (struct request_queue *, struct request *);
typedef void (elevator_deactivate_req_fn) (struct request_queue *, struct request *);

typedef int (elevator_init_fn) (struct request_queue *,
				struct elevator_type *e);
typedef void (elevator_exit_fn) (struct elevator_queue *);
typedef void (elevator_registered_fn) (struct request_queue *);

struct elevator_ops
{
	/*找到合适的req，request和bio合并的时候调用*/
	/*cfq_merge*/
	elevator_merge_fn *elevator_merge_fn;
	
	/*
	合并了两个req ***之后***需要的操作    

	blk_queue_bio
		attempt_back_merge
			elv_merge_requests
				elevator_merge_req_fn
		elv_merged_request
			elevator_merged_fn
	 */
	 /*cfq_merged_request*/
	elevator_merged_fn *elevator_merged_fn;
	
	/* elv_merge_requests 合并两个req， 因为req + new_bio 
	可能会和前一个req或者后一个req合并*/
	/*
		处理merge 两个req 的函数
		attempt_merge
			elv_merge_requests
				elevator_merge_req_fn
	*/
	elevator_merge_req_fn *elevator_merge_req_fn;
	
	/* bio能否merge到rq里面*/
	/*cfq_allow_merge*/
	elevator_allow_bio_merge_fn *elevator_allow_bio_merge_fn;

	/*两个req之间是否合并*/
	elevator_allow_rq_merge_fn *elevator_allow_rq_merge_fn;
	/*合并了bio之后的一些附加操作*/
	/*cfq_bio_merged*/
	elevator_bio_merged_fn *elevator_bio_merged_fn;

	/*重新挂载到q->queue_head上*/
	/*cfq_dispatch_requests*/
	elevator_dispatch_fn *elevator_dispatch_fn;

	/*cfq_insert_request,-------增加一个新请求到调度器*/
	/*添加req到调度层上*/
	elevator_add_req_fn *elevator_add_req_fn;

	/*cfq_activate_request,----这个相当于让block层看到这个request*/
	elevator_activate_req_fn *elevator_activate_req_fn;

	/*cfq_deactivate_request,---这个就是block驱动再推迟这个请求*/
	elevator_deactivate_req_fn *elevator_deactivate_req_fn;

	/*__blk_put_request 会调用这个函数*/
	elevator_completed_req_fn *elevator_completed_req_fn;

	/*找前一个req*/
	elevator_request_list_fn *elevator_former_req_fn;
	/*找后一个req*/
	elevator_request_list_fn *elevator_latter_req_fn;

	/*cfq_init_icq,--------icq的构造函数*/
	elevator_init_icq_fn *elevator_init_icq_fn;	/* see iocontext.h */

	/*cfq_exit_icq,--------icq的析构函数*/
	elevator_exit_icq_fn *elevator_exit_icq_fn;	/* ditto */

	/*elv_set_request*/
	/*cfq_set_request,------创建请求时填充req的一些必要字段*/
	elevator_set_req_fn *elevator_set_req_fn;
	elevator_put_req_fn *elevator_put_req_fn;

	elevator_may_queue_fn *elevator_may_queue_fn;

	elevator_init_fn *elevator_init_fn; /*给rq增加一个elevator*/
	elevator_exit_fn *elevator_exit_fn;
	elevator_registered_fn *elevator_registered_fn;
};

struct blk_mq_alloc_data;
struct blk_mq_hw_ctx;

struct elevator_mq_ops {
	int (*init_sched)(struct request_queue *, struct elevator_type *);
	void (*exit_sched)(struct elevator_queue *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);

	bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
	bool (*bio_merge)(struct blk_mq_hw_ctx *, struct bio *);
	int (*request_merge)(struct request_queue *q, struct request **, struct bio *);
	void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
	void (*requests_merged)(struct request_queue *, struct request *, struct request *);
	void (*limit_depth)(unsigned int, struct blk_mq_alloc_data *);
	void (*prepare_request)(struct request *, struct bio *bio);
	void (*finish_request)(struct request *);
	void (*insert_requests)(struct blk_mq_hw_ctx *, struct list_head *, bool);
	struct request *(*dispatch_request)(struct blk_mq_hw_ctx *);
	bool (*has_work)(struct blk_mq_hw_ctx *);
	void (*completed_request)(struct request *);
	void (*started_request)(struct request *);
	void (*requeue_request)(struct request *);
	struct request *(*former_request)(struct request_queue *, struct request *);
	struct request *(*next_request)(struct request_queue *, struct request *);
	void (*init_icq)(struct io_cq *);
	void (*exit_icq)(struct io_cq *);
};

#define ELV_NAME_MAX	(16)

struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};

/*
 * identifies an elevator type, such as AS or deadline
 */
struct elevator_type
{
	/* managed by elevator core */
	struct kmem_cache *icq_cache;

	/* fields provided by elevator implementation */
	union {
		struct elevator_ops sq;
		struct elevator_mq_ops mq;
	} ops;
	size_t icq_size;	/* see iocontext.h */
	size_t icq_align;	/* ditto */
	struct elv_fs_entry *elevator_attrs;
	char elevator_name[ELV_NAME_MAX];
	struct module *elevator_owner;
	bool uses_mq;
#ifdef CONFIG_BLK_DEBUG_FS
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
#endif

	/* managed by elevator core */
	char icq_cache_name[ELV_NAME_MAX + 6];	/* elvname + "_io_cq" */
	struct list_head list;
};

#define ELV_HASH_BITS 6

void elv_rqhash_del(struct request_queue *q, struct request *rq);
void elv_rqhash_add(struct request_queue *q, struct request *rq);
void elv_rqhash_reposition(struct request_queue *q, struct request *rq);
struct request *elv_rqhash_find(struct request_queue *q, sector_t offset);

/*
 * each queue has an elevator_queue associated with it
 */
struct elevator_queue
{
	struct elevator_type *type;
	void *elevator_data;
	struct kobject kobj;
	struct mutex sysfs_lock;
	unsigned int registered:1;
	unsigned int uses_mq:1;
	DECLARE_HASHTABLE(hash, ELV_HASH_BITS); /*rq挂在这里， key = end sector*/
};

/*
 * block elevator interface
 */
extern void elv_dispatch_sort(struct request_queue *, struct request *);
extern void elv_dispatch_add_tail(struct request_queue *, struct request *);
extern void elv_add_request(struct request_queue *, struct request *, int);
extern void __elv_add_request(struct request_queue *, struct request *, int);
extern enum elv_merge elv_merge(struct request_queue *, struct request **,
		struct bio *);
extern void elv_merge_requests(struct request_queue *, struct request *,
			       struct request *);
extern void elv_merged_request(struct request_queue *, struct request *,
		enum elv_merge);
extern void elv_bio_merged(struct request_queue *q, struct request *,
				struct bio *);
extern bool elv_attempt_insert_merge(struct request_queue *, struct request *);
extern void elv_requeue_request(struct request_queue *, struct request *);
extern struct request *elv_former_request(struct request_queue *, struct request *);
extern struct request *elv_latter_request(struct request_queue *, struct request *);
extern int elv_register_queue(struct request_queue *q);
extern void elv_unregister_queue(struct request_queue *q);
extern int elv_may_queue(struct request_queue *, unsigned int);
extern void elv_completed_request(struct request_queue *, struct request *);
extern int elv_set_request(struct request_queue *q, struct request *rq,
			   struct bio *bio, gfp_t gfp_mask);
extern void elv_put_request(struct request_queue *, struct request *);
extern void elv_drain_elevator(struct request_queue *);

/*
 * io scheduler registration
 */
extern void __init load_default_elevator_module(void);
extern int elv_register(struct elevator_type *);
extern void elv_unregister(struct elevator_type *);

/*
 * io scheduler sysfs switching
 */
extern ssize_t elv_iosched_show(struct request_queue *, char *);
extern ssize_t elv_iosched_store(struct request_queue *, const char *, size_t);

extern int elevator_init(struct request_queue *, char *);
extern void elevator_exit(struct request_queue *, struct elevator_queue *);
extern bool elv_bio_merge_ok(struct request *, struct bio *);
extern struct elevator_queue *elevator_alloc(struct request_queue *,
					struct elevator_type *);

/*
 * Helper functions.
 */
extern struct request *elv_rb_former_request(struct request_queue *, struct request *);
extern struct request *elv_rb_latter_request(struct request_queue *, struct request *);

/*
 * rb support functions.
 */
extern void elv_rb_add(struct rb_root *, struct request *);
extern void elv_rb_del(struct rb_root *, struct request *);
extern struct request *elv_rb_find(struct rb_root *, sector_t);

/*
 * Insertion selection
 */
#define ELEVATOR_INSERT_FRONT	1
#define ELEVATOR_INSERT_BACK	2
#define ELEVATOR_INSERT_SORT	3
#define ELEVATOR_INSERT_REQUEUE	4
#define ELEVATOR_INSERT_FLUSH	5
#define ELEVATOR_INSERT_SORT_MERGE	6

/*
 * return values from elevator_may_queue_fn
 */
enum {
	ELV_MQUEUE_MAY,
	ELV_MQUEUE_NO,
	ELV_MQUEUE_MUST,
};

#define rq_end_sector(rq)	(blk_rq_pos(rq) + blk_rq_sectors(rq))
#define rb_entry_rq(node)	rb_entry((node), struct request, rb_node)

#define rq_entry_fifo(ptr)	list_entry((ptr), struct request, queuelist)
#define rq_fifo_clear(rq)	list_del_init(&(rq)->queuelist)

#else /* CONFIG_BLOCK */

static inline void load_default_elevator_module(void) { }

#endif /* CONFIG_BLOCK */
#endif
