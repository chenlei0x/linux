/*
 * linux/ipc/namespace.c
 * Copyright (C) 2006 Pavel Emelyanov <xemul@openvz.org> OpenVZ, SWsoft Inc.
 */

#include <linux/ipc.h>
#include <linux/msg.h>
#include <linux/ipc_namespace.h>
#include <linux/rcupdate.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>

#include "util.h"

static struct ucounts *inc_ipc_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_IPC_NAMESPACES);
}

static void dec_ipc_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_IPC_NAMESPACES);
}

static struct ipc_namespace *create_ipc_ns(struct user_namespace *user_ns,
					   struct ipc_namespace *old_ns)
{
	struct ipc_namespace *ns;
	struct ucounts *ucounts;
	int err;

	err = -ENOSPC;
	ucounts = inc_ipc_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = kmalloc(sizeof(struct ipc_namespace), GFP_KERNEL);
	if (ns == NULL)
		goto fail_dec;

	err = proc_alloc_inum(&ns->proc_inum);
	if (err)
		goto fail_free;

	atomic_set(&ns->count, 1);
	ns->user_ns = get_user_ns(user_ns);
	ns->ucounts = ucounts;

	err = mq_init_ns(ns);
	if (err)
		goto fail_put;
	atomic_inc(&nr_ipc_ns);

	sem_init_ns(ns);
	msg_init_ns(ns);
	shm_init_ns(ns);

	return ns;

fail_put:
	put_user_ns(ns->user_ns);
	proc_free_inum(ns->proc_inum);
fail_free:
	kfree(ns);
fail_dec:
	dec_ipc_namespaces(ucounts);
fail:
	return ERR_PTR(err);
}

struct ipc_namespace *copy_ipcs(unsigned long flags,
	struct user_namespace *user_ns, struct ipc_namespace *ns)
{
	if (!(flags & CLONE_NEWIPC))
		return get_ipc_ns(ns);
	return create_ipc_ns(user_ns, ns);
}

/*
 * free_ipcs - free all ipcs of one type
 * @ns:   the namespace to remove the ipcs from
 * @ids:  the table of ipcs to free
 * @free: the function called to free each individual ipc
 *
 * Called for each kind of ipc when an ipc_namespace exits.
 */
void free_ipcs(struct ipc_namespace *ns, struct ipc_ids *ids,
	       void (*free)(struct ipc_namespace *, struct kern_ipc_perm *))
{
	struct kern_ipc_perm *perm;
	int next_id;
	int total, in_use;

	down_write(&ids->rwsem);

	in_use = ids->in_use;

	for (total = 0, next_id = 0; total < in_use; next_id++) {
		perm = idr_find(&ids->ipcs_idr, next_id);
		if (perm == NULL)
			continue;
		rcu_read_lock();
		ipc_lock_object(perm);
		free(ns, perm);
		total++;
	}
	up_write(&ids->rwsem);
}

static void free_ipc_ns(struct ipc_namespace *ns)
{
	sem_exit_ns(ns);
	msg_exit_ns(ns);
	shm_exit_ns(ns);
	atomic_dec(&nr_ipc_ns);

	dec_ipc_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	proc_free_inum(ns->proc_inum);
	kfree(ns);
}

/*
 * put_ipc_ns - drop a reference to an ipc namespace.
 * @ns: the namespace to put
 *
 * If this is the last task in the namespace exiting, and
 * it is dropping the refcount to 0, then it can race with
 * a task in another ipc namespace but in a mounts namespace
 * which has this ipcns's mqueuefs mounted, doing some action
 * with one of the mqueuefs files.  That can raise the refcount.
 * So dropping the refcount, and raising the refcount when
 * accessing it through the VFS, are protected with mq_lock.
 *
 * (Clearly, a task raising the refcount on its own ipc_ns
 * needn't take mq_lock since it can't race with the last task
 * in the ipcns exiting).
 */
void put_ipc_ns(struct ipc_namespace *ns)
{
	if (atomic_dec_and_lock(&ns->count, &mq_lock)) {
		mq_clear_sbinfo(ns);
		spin_unlock(&mq_lock);
		mq_put_mnt(ns);
		free_ipc_ns(ns);
	}
}

static void *ipcns_get(struct task_struct *task)
{
	struct ipc_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy)
		ns = get_ipc_ns(nsproxy->ipc_ns);
	task_unlock(task);

	return ns;
}

static void ipcns_put(void *ns)
{
	return put_ipc_ns(ns);
}

static int ipcns_install(struct nsproxy *nsproxy, void *new)
{
	struct ipc_namespace *ns = new;
	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	/* Ditch state from the old ipc namespace */
	exit_sem(current);
	put_ipc_ns(nsproxy->ipc_ns);
	nsproxy->ipc_ns = get_ipc_ns(ns);
	return 0;
}

static unsigned int ipcns_inum(void *vp)
{
	struct ipc_namespace *ns = vp;

	return ns->proc_inum;
}

const struct proc_ns_operations ipcns_operations = {
	.name		= "ipc",
	.type		= CLONE_NEWIPC,
	.get		= ipcns_get,
	.put		= ipcns_put,
	.install	= ipcns_install,
	.inum		= ipcns_inum,
};
