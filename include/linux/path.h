/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;

/*
 * 一个mnt下的哪个文件dentry
 * mnt用来区分哪个mount point 因为mnt可以被用来转换为
 * struct mount
 * 一个mnt_root 可能被多个mount结构体引用
 */
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __randomize_layout;

extern void path_get(const struct path *);
extern void path_put(const struct path *);

static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

static inline void path_put_init(struct path *path)
{
	path_put(path);
	*path = (struct path) { };
}

#endif  /* _LINUX_PATH_H */
