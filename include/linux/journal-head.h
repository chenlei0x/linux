/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/journal-head.h
 *
 * buffer_head fields for JBD
 *
 * 27 May 2001 Andrew Morton
 *	Created - pulled out of fs.h
 */

#ifndef JOURNAL_HEAD_H_INCLUDED
#define JOURNAL_HEAD_H_INCLUDED

typedef unsigned int		tid_t;		/* Unique transaction ID */
typedef struct transaction_s	transaction_t;	/* Compound transaction type */


struct buffer_head;

struct journal_head {
	/*
	 * Points back to our buffer_head. [jbd_lock_bh_journal_head()]
	 */
	struct buffer_head *b_bh;

	/*
	 * Reference count - see description in journal.c
	 * [jbd_lock_bh_journal_head()]
	 */
	int b_jcount;

	/*
	 * Journalling list for this buffer [jbd_lock_bh_state()]
	 * NOTE: We *cannot* combine this with b_modified into a bitfield
	 * as gcc would then (which the C standard allows but which is
	 * very unuseful) make 64-bit accesses to the bitfield and clobber
	 * b_jcount if its update races with bitfield modification.
	 *
	 * 指向jh所处在transaction上的哪个队列 t_buffers t_forgett t_shadowlist t_reserved_list
	 */
	unsigned b_jlist;

	/*
	 * This flag signals the buffer has been modified by
	 * the currently running transaction
	 * [jbd_lock_bh_state()]
	 *
	 * jbd2_journal_dirty_metadata 会置为1
	 */
	unsigned b_modified;

	/*
	 * Copy of the buffer data frozen for writing to the log.
	 * [jbd_lock_bh_state()]
	 */
	 /*frozen 是调用get_undo_access时备份的数据，也就是修改之前的数据*/

	/*

	这个函数是处理一种特殊的元数据块的----磁盘块位图。
	磁盘块位图是文件系统用于记录磁盘块使用情况的一种结构，块中的每一个位表
	示相应的磁盘块是否被占用。如果空闲，则为0，否则为1。磁盘快位图之所以特殊，
	在于一个磁盘块不能被两个文件同时占用，他要么是空闲的，要么在同一时刻只
	能被一个文件占用。对这种元数据块的修改，要取得undo权限，为什么呢？
	
	假设handle1中，删除了一个数据块b1，则对应bitmap1中的位被清掉，这个操作
	属于transaction1.此时，再进行磁盘块的分配和释放，则我们必须要知道bitmap1
	是否已被提交到日志中了。因为，如果bitmap1已经被提交到日志中，则表示handle1
	已经确实完成了，即使现在发生崩溃，删除b1的操作也可以是重现的。但是如果bitmap1
	没有被提交到日志中，则表示handle并没有完成，那么，你说此时数据块b1是已
	经被删除了还是没有被删除？从物理的角度看b1并没有被删除，因为实际上磁盘块位图
	并没有被改变。
	
	此时，如果重新分配磁盘块b1，我们必须等待，直到t1提交完成，以保证handle1的可恢复性。
	因此，我们从磁盘块位图中分配磁盘块时，只可以分配在缓冲区中和日志中该位都为0
	的磁盘块。为此jbd在取得磁盘块位图缓冲区的写权限是，必须将缓冲区当前的内容考
	本一份，以备分配磁盘块时使用。
	
	journal_get_undo_access()与journal_get_write_access()函数基本类似，但是注意在
	调用do_get_write_access()函数时最后一个参数是1，表示force_copy为真，表示一定要
	将缓冲区当前的数据冻结起来。

	*/
	char *b_frozen_data;

	/*
	 * Pointer to a saved copy of the buffer containing no uncommitted
	 * deallocation references, so that allocations can avoid overwriting
	 * uncommitted deletes. [jbd_lock_bh_state()]
	 */
	char *b_committed_data;

	/*
	 * Pointer to the compound transaction which owns this buffer's
	 * metadata: either the running transaction or the committing
	 * transaction (if there is one).  Only applies to buffers on a
	 * transaction's data or metadata journaling list.
	 * [j_list_lock] [jbd_lock_bh_state()]
	 * Either of these locks is enough for reading, both are needed for
	 * changes.
	 */
	transaction_t *b_transaction;

	/*
	 * Pointer to the running compound transaction which is currently
	 * modifying the buffer's metadata, if there was already a transaction
	 * committing it when the new transaction touched it.
	 * [t_list_lock] [jbd_lock_bh_state()]
	 *
	 * 新的transaction 动了这个bh,需要用这个指针指向他
	 */
	transaction_t *b_next_transaction;

	/*
	 * Doubly-linked list of buffers on a transaction's data, metadata or
	 * forget queue. [t_list_lock] [jbd_lock_bh_state()]
	 */
	 /*连在transaction 的 t_buffers t_forgett t_shadowlist t_reserved_list其中之一上 */
	struct journal_head *b_tnext, *b_tprev;

	/*
	 * Pointer to the compound transaction against which this buffer
	 * is checkpointed.  Only dirty buffers can be checkpointed.
	 * [j_list_lock]
	 */
	transaction_t *b_cp_transaction;

	/*
	 * Doubly-linked list of buffers still remaining to be flushed
	 * before an old transaction can be checkpointed.
	 * [j_list_lock]
	 */
	struct journal_head *b_cpnext, *b_cpprev;

	/* Trigger type */
	struct jbd2_buffer_trigger_type *b_triggers;

	/* Trigger type for the committing transaction's frozen data */
	struct jbd2_buffer_trigger_type *b_frozen_triggers;
};

#endif		/* JOURNAL_HEAD_H_INCLUDED */
