/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef	__XFS_INODE_FORK_H__
#define	__XFS_INODE_FORK_H__

struct xfs_inode_log_item;
struct xfs_dinode;

/*
 * The following xfs_ext_irec_t struct introduces a second (top) level
 * to the in-core extent allocation scheme. These structs are allocated
 * in a contiguous block, creating an indirection array where each entry
 * (irec) contains a pointer to a buffer of in-core extent records which
 * it manages. Each extent buffer is 4k in size, since 4k is the system
 * page size on Linux i386 and systems with larger page sizes don't seem
 * to gain much, if anything, by using their native page size as the
 * extent buffer size. Also, using 4k extent buffers everywhere provides
 * a consistent interface for CXFS across different platforms.
 *
 * There is currently no limit on the number of irec's (extent lists)
 * allowed, so heavily fragmented files may require an indirection array
 * which spans multiple system pages of memory. The number of extents
 * which would require this amount of contiguous memory is very large
 * and should not cause problems in the foreseeable future. However,
 * if the memory needed for the contiguous array ever becomes a problem,
 * it is possible that a third level of indirection may be required.
 *
 * irec ---- indirect rec
 */
typedef struct xfs_ext_irec {
	xfs_bmbt_rec_host_t *er_extbuf;	/* block of extent records */
	xfs_extnum_t	er_extoff;	/* extent offset in file */
	/*最大XFS_LINEAR_EXTS*/
	xfs_extnum_t	er_extcount;	/* number of extents in page/block */
} xfs_ext_irec_t;

/*
 * File incore extent information, present for each of data & attr forks.
 */
#define	XFS_IEXT_BUFSZ		4096
/*当inode 以 linear (direct) extent list 形式组织extent时,
extent 数量限制*/
#define	XFS_LINEAR_EXTS		(XFS_IEXT_BUFSZ / (uint)sizeof(xfs_bmbt_rec_t))
#define	XFS_INLINE_EXTS		2
#define	XFS_INLINE_DATA		32
typedef struct xfs_ifork {

	/*if_bytese 和 if_real_bytes 可以看 	xfs_idata_realloc函数*/
	/*xfs_iext_irec_init 可以看以下两个字段的初始化*/
	/*
	1) XFS_IFINLINE:
		if bytes: = di_size
		if real bytes = 申请内存的长度 >= di size
	2) XFS_IFEXTENTS （分inline 和 non-inline两种）
		if_bytes = nex * sizeof(xfs_bmbt_rec_t);
		         = inode extent 总数量 * sizeof(xfs_bmbt_rec_t);
		if real bytes = 申请内存的长度
	*/
	int			if_bytes;	/* bytes in if_u1 */
	/*
	如果 ifp->if_flags   有 XFS_IFEXTIREC ////indirect
		if_ext_irec 长度 = ifp->if_real_bytes / XFS_IEXT_BUFSZ;
	否则
		if_bytes = fp->if_u1.if_extents 数组所在内存的长度 ////direct
		if_real_bytes = fp->if_u1.if_extents 数组实际使用长度(申请的内存长度可能较长)
		如果 f_read_bytes == 0: ////inline
			所有的extent都在if_u2.if_inline_ext 数组中	


	*/
	int			if_real_bytes;	/* bytes allocated in if_u1 */
	struct xfs_btree_block	*if_broot;	/* file's incore btree root */
	short			if_broot_bytes;	/* bytes allocated for root */
	unsigned char		if_flags;	/* per-fork flags */
	/*这个分级应该是 
	 * inline data
	 * inline ext
	 * if extents (一级) ext数量最多 XFS_LINEAR_EXTS
	 * if ext irec数组 (二级数组)
	 */
	union {
		xfs_bmbt_rec_host_t *if_extents;/* linear map file exts */
		/*
		 * rec数组 一个rec 有一个buf(长度为4K), 里面包含的都是extent,
		 * xfs_iext_realloc_indirect 会根据长度重新分配
		 *
		 * if_real_bytes = 数组长度 * 4K
		 */
		xfs_ext_irec_t	*if_ext_irec;	/* irec map file exts */
		/*用来便捷的取数据的指针,可能等于 ifp->if_u2.if_inline_data, 
		也可能指向新申请的内存*/
		char		*if_data;	/* inline file data */
	} if_u1;
	union {
		xfs_bmbt_rec_host_t if_inline_ext[XFS_INLINE_EXTS];
						/* very small file extents */
		char		if_inline_data[XFS_INLINE_DATA];
						/* very small file data */
		xfs_dev_t	if_rdev;	/* dev number if special */
		uuid_t		if_uuid;	/* mount point value */
	} if_u2;
} xfs_ifork_t;

/*
 * Per-fork incore inode flags.
 */
 /*对应local fork*/
#define	XFS_IFINLINE	0x01	/* Inline data is read in */
#define	XFS_IFEXTENTS	0x02	/* All extent pointers are read in */
#define	XFS_IFBROOT	0x04	/* i_broot points to the bmap b-tree root */
#define	XFS_IFEXTIREC	0x08	/* Indirection array of extent blocks */

/*
 * Fork handling.
 * di_forkoff 表明data fork 和 xattr fork的分界线
 */

#define XFS_IFORK_Q(ip)			((ip)->i_d.di_forkoff != 0)
#define XFS_IFORK_BOFF(ip)		((int)((ip)->i_d.di_forkoff << 3))

/*ip ： xfs_inode_t 内存中的inode节点*/
#define XFS_IFORK_PTR(ip,w)		\
	((w) == XFS_DATA_FORK ? \
		&(ip)->i_df : \
		((w) == XFS_ATTR_FORK ? \
			(ip)->i_afp : \
			(ip)->i_cowfp))
/*如果不存在分界线,那么literal area 都是data fork的*/
#define XFS_IFORK_DSIZE(ip) \
	(XFS_IFORK_Q(ip) ? \
		XFS_IFORK_BOFF(ip) : \
		XFS_LITINO((ip)->i_mount, (ip)->i_d.di_version))

/*如果attr fork存在,则分界线肯定存在,
literal area - data fork size的*/
#define XFS_IFORK_ASIZE(ip) \
	(XFS_IFORK_Q(ip) ? \
		XFS_LITINO((ip)->i_mount, (ip)->i_d.di_version) - \
			XFS_IFORK_BOFF(ip) : \
		0)
#define XFS_IFORK_SIZE(ip,w) \
	((w) == XFS_DATA_FORK ? \
		XFS_IFORK_DSIZE(ip) : \
		((w) == XFS_ATTR_FORK ? \
			XFS_IFORK_ASIZE(ip) : \
			0))
#define XFS_IFORK_FORMAT(ip,w) \
	((w) == XFS_DATA_FORK ? \
		(ip)->i_d.di_format : \
		((w) == XFS_ATTR_FORK ? \
			(ip)->i_d.di_aformat : \
			(ip)->i_cformat))
#define XFS_IFORK_FMT_SET(ip,w,n) \
	((w) == XFS_DATA_FORK ? \
		((ip)->i_d.di_format = (n)) : \
		((w) == XFS_ATTR_FORK ? \
			((ip)->i_d.di_aformat = (n)) : \
			((ip)->i_cformat = (n))))
#define XFS_IFORK_NEXTENTS(ip,w) \
	((w) == XFS_DATA_FORK ? \
		(ip)->i_d.di_nextents : \
		((w) == XFS_ATTR_FORK ? \
			(ip)->i_d.di_anextents : \
			(ip)->i_cnextents))
#define XFS_IFORK_NEXT_SET(ip,w,n) \
	((w) == XFS_DATA_FORK ? \
		((ip)->i_d.di_nextents = (n)) : \
		((w) == XFS_ATTR_FORK ? \
			((ip)->i_d.di_anextents = (n)) : \
			((ip)->i_cnextents = (n))))

/*fork 数据区可以容纳多少个ext*/
#define XFS_IFORK_MAXEXT(ip, w) \
	(XFS_IFORK_SIZE(ip, w) / sizeof(xfs_bmbt_rec_t))

struct xfs_ifork *xfs_iext_state_to_fork(struct xfs_inode *ip, int state);

int		xfs_iformat_fork(struct xfs_inode *, struct xfs_dinode *);
void		xfs_iflush_fork(struct xfs_inode *, struct xfs_dinode *,
				struct xfs_inode_log_item *, int);
void		xfs_idestroy_fork(struct xfs_inode *, int);
void		xfs_idata_realloc(struct xfs_inode *, int, int);
void		xfs_iroot_realloc(struct xfs_inode *, int, int);
int		xfs_iread_extents(struct xfs_trans *, struct xfs_inode *, int);
int		xfs_iextents_copy(struct xfs_inode *, struct xfs_bmbt_rec *,
				  int);
void		xfs_init_local_fork(struct xfs_inode *, int, const void *, int);

struct xfs_bmbt_rec_host *
		xfs_iext_get_ext(struct xfs_ifork *, xfs_extnum_t);
xfs_extnum_t	xfs_iext_count(struct xfs_ifork *);
void		xfs_iext_insert(struct xfs_inode *, xfs_extnum_t, xfs_extnum_t,
				struct xfs_bmbt_irec *, int);
void		xfs_iext_add(struct xfs_ifork *, xfs_extnum_t, int);
void		xfs_iext_add_indirect_multi(struct xfs_ifork *, int,
					    xfs_extnum_t, int);
void		xfs_iext_remove(struct xfs_inode *, xfs_extnum_t, int, int);
void		xfs_iext_remove_inline(struct xfs_ifork *, xfs_extnum_t, int);
void		xfs_iext_remove_direct(struct xfs_ifork *, xfs_extnum_t, int);
void		xfs_iext_remove_indirect(struct xfs_ifork *, xfs_extnum_t, int);
void		xfs_iext_realloc_direct(struct xfs_ifork *, int);
void		xfs_iext_direct_to_inline(struct xfs_ifork *, xfs_extnum_t);
void		xfs_iext_inline_to_direct(struct xfs_ifork *, int);
void		xfs_iext_destroy(struct xfs_ifork *);
struct xfs_bmbt_rec_host *
		xfs_iext_bno_to_ext(struct xfs_ifork *, xfs_fileoff_t, int *);
struct xfs_ext_irec *
		xfs_iext_bno_to_irec(struct xfs_ifork *, xfs_fileoff_t, int *);
struct xfs_ext_irec *
		xfs_iext_idx_to_irec(struct xfs_ifork *, xfs_extnum_t *, int *,
				     int);
void		xfs_iext_irec_init(struct xfs_ifork *);
struct xfs_ext_irec *
		xfs_iext_irec_new(struct xfs_ifork *, int);
void		xfs_iext_irec_remove(struct xfs_ifork *, int);
void		xfs_iext_irec_compact(struct xfs_ifork *);
void		xfs_iext_irec_compact_pages(struct xfs_ifork *);
void		xfs_iext_irec_compact_full(struct xfs_ifork *);
void		xfs_iext_irec_update_extoffs(struct xfs_ifork *, int, int);

bool		xfs_iext_lookup_extent(struct xfs_inode *ip,
			struct xfs_ifork *ifp, xfs_fileoff_t bno,
			xfs_extnum_t *idxp, struct xfs_bmbt_irec *gotp);
bool		xfs_iext_get_extent(struct xfs_ifork *ifp, xfs_extnum_t idx,
			struct xfs_bmbt_irec *gotp);
void		xfs_iext_update_extent(struct xfs_ifork *ifp, xfs_extnum_t idx,
			struct xfs_bmbt_irec *gotp);

extern struct kmem_zone	*xfs_ifork_zone;

extern void xfs_ifork_init_cow(struct xfs_inode *ip);

#endif	/* __XFS_INODE_FORK_H__ */
