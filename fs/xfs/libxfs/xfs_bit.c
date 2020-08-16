/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
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
#include "xfs.h"
#include "xfs_log_format.h"
#include "xfs_bit.h"

/*
 * XFS bit manipulation routines, used in non-realtime code.
 */

/*
 * Return whether bitmap is empty.
 * Size is number of words in the bitmap, which is padded to word boundary
 * Returns 1 for empty, 0 for non-empty.
 */
int
xfs_bitmap_empty(uint *map, uint size)
{
	uint i;

	for (i = 0; i < size; i++) {
		if (map[i] != 0)
			return 0;
	}

	return 1;
}

/*
 * Count the number of contiguous bits set in the bitmap starting with bit
 * start_bit.  Size is the size of the bitmap in words.
 * @size = map的长度(字节数)/sizeof(uint)
 *
 * 用来计算从@start_bit开始连续由多少个bit为1,如果start_bit所在bit为0,则返回0
 */
int
xfs_contig_bits(uint *map, uint	size, uint start_bit)
{
	uint * p = ((unsigned int *) map) + (start_bit >> BIT_TO_WORD_SHIFT);
	uint result = 0;
	uint tmp;

	size <<= BIT_TO_WORD_SHIFT;

	ASSERT(start_bit < size);
	/*size 为start_bit所在的uint*/
	size -= start_bit & ~(NBWORD - 1);
	start_bit &= (NBWORD - 1);
	/*if内用来算不整齐的部分*/
	if (start_bit) {
		tmp = *p++;
		/* set to one first offset bits prior to start */
		/*[0 ~ start_bit)之间依然保持为1, [start_bit ~ NBWORD) 为0*/
		/*
		 * 这里tmp 进行 或运算为了看[start_bit ~ NBWORD)中间时什么情况,
		 * 如果全为1, 那么tmp 或运算之后全为1, 
		 * 如果不是全为1,那么tmp或运算之后肯定不是全为1,那也就是说出现了不连续的状况
		 */
		tmp |= (~0U >> (NBWORD-start_bit));
		if (tmp != ~0U)
			goto found;
		result += NBWORD;
		size -= NBWORD;
	}
	while (size) {
		/*该word内出现了不连续为1的情况,那么ffz的返回值就是连续多少个1的情况*/
		if ((tmp = *p++) != ~0U)
			goto found;
		result += NBWORD;
		size -= NBWORD;
	}
	return result - start_bit;
found:
	return result + ffz(tmp) - start_bit;
}

/*
 * This takes the bit number to start looking from and
 * returns the next set bit from there.  It returns -1
 * if there are no more bits set or the start bit is
 * beyond the end of the bitmap.
 *
 * Size is the number of words, not bytes, in the bitmap.
 *
 * 从start_bit开始,计算下一个为1的bit index. 如果start_bit所在
 * 本身就为1,则返回start_bit
 */
int xfs_next_bit(uint *map, uint size, uint start_bit)
{
	uint * p = ((unsigned int *) map) + (start_bit >> BIT_TO_WORD_SHIFT);
	uint result = start_bit & ~(NBWORD - 1);
	uint tmp;

	size <<= BIT_TO_WORD_SHIFT;

	if (start_bit >= size)
		return -1;
	size -= result;
	start_bit &= (NBWORD - 1);
	if (start_bit) {
		tmp = *p++;
		/* set to zero first offset bits prior to start */
		tmp &= (~0U << start_bit);
		if (tmp != 0U)
			goto found;
		result += NBWORD;
		size -= NBWORD;
	}
	while (size) {
		if ((tmp = *p++) != 0U)
			goto found;
		result += NBWORD;
		size -= NBWORD;
	}
	return -1;
found:
	return result + ffs(tmp) - 1;
}
