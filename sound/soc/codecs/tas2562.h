/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * tas2562.h - ALSA SoC Texas Instruments TAS2562 Mono Audio Amplifier
 *
 * Copyright (C) 2019 Texas Instruments Incorporated -  http://www.ti.com
 *
 * Author: Dan Murphy <dmurphy@ti.com>
 */

#ifndef __TAS2562_H__
#define __TAS2562_H__

#define TAS2562_PAGE_CTRL	0x00

#define TAS2562_REG(page, reg)	((page * 128) + reg)

#define TAS2562_SW_RESET	TAS2562_REG(0, 0x01)
#define TAS2562_PWR_CTRL	TAS2562_REG(0, 0x02)
#define TAS2562_PB_CFG1		TAS2562_REG(0, 0x03)
#define TAS2562_MISC_CFG1	TAS2562_REG(0, 0x04)
#define TAS2562_MISC_CFG2	TAS2562_REG(0, 0x05)

#define TAS2562_TDM_CFG0	TAS2562_REG(0, 0x06)
#define TAS2562_TDM_CFG1	TAS2562_REG(0, 0x07)
#define TAS2562_TDM_CFG2	TAS2562_REG(0, 0x08)
#define TAS2562_TDM_CFG3	TAS2562_REG(0, 0x09)
#define TAS2562_TDM_CFG4	TAS2562_REG(0, 0x0a)
#define TAS2562_TDM_CFG5	TAS2562_REG(0, 0x0b)
#define TAS2562_TDM_CFG6	TAS2562_REG(0, 0x0c)
#define TAS2562_TDM_CFG7	TAS2562_REG(0, 0x0d)
#define TAS2562_TDM_CFG8	TAS2562_REG(0, 0x0e)
#define TAS2562_TDM_CFG9	TAS2562_REG(0, 0x0f)
#define TAS2562_TDM_CFG10	TAS2562_REG(0, 0x10)
#define TAS2562_TDM_DET		TAS2562_REG(0, 0x11)
#define TAS2562_REV_ID		TAS2562_REG(0, 0x7d)

/* Page 2 */
#define TAS2562_DVC_CFG1	TAS2562_REG(2, 0x01)
#define TAS2562_DVC_CFG2	TAS2562_REG(2, 0x02)

#define TAS2562_RESET	BIT(0)

#define TAS2562_MODE_MASK	0x3
#define TAS2562_ACTIVE		0x0
#define TAS2562_MUTE		0x1
#define TAS2562_SHUTDOWN	0x2

#define TAS2562_TDM_CFG1_RX_EDGE_MASK	BIT(0)
#define TAS2562_TDM_CFG1_RX_FALLING	1
#define TAS2562_TDM_CFG1_RX_OFFSET_MASK	GENMASK(4, 0)

#define TAS2562_TDM_CFG0_RAMPRATE_MASK		BIT(5)
#define TAS2562_TDM_CFG0_RAMPRATE_44_1		BIT(5)
#define TAS2562_TDM_CFG0_SAMPRATE_MASK		GENMASK(3, 1)
#define TAS2562_TDM_CFG0_SAMPRATE_7305_8KHZ	0x0
#define TAS2562_TDM_CFG0_SAMPRATE_14_7_16KHZ	0x1
#define TAS2562_TDM_CFG0_SAMPRATE_22_05_24KHZ	0x2
#define TAS2562_TDM_CFG0_SAMPRATE_29_4_32KHZ	0x3
#define TAS2562_TDM_CFG0_SAMPRATE_44_1_48KHZ	0x4
#define TAS2562_TDM_CFG0_SAMPRATE_88_2_96KHZ	0x5
#define TAS2562_TDM_CFG0_SAMPRATE_176_4_192KHZ	0x6

#define TAS2562_TDM_CFG2_RIGHT_JUSTIFY	BIT(6)

#define TAS2562_TDM_CFG2_RXLEN_MASK	GENMASK(1, 0)
#define TAS2562_TDM_CFG2_RXLEN_16B	0x0
#define TAS2562_TDM_CFG2_RXLEN_24B	BIT(0)
#define TAS2562_TDM_CFG2_RXLEN_32B	BIT(1)

#define TAS2562_TDM_CFG2_RXWLEN_MASK	GENMASK(3, 2)
#define TAS2562_TDM_CFG2_RXWLEN_16B	0x0
#define TAS2562_TDM_CFG2_RXWLEN_20B	BIT(2)
#define TAS2562_TDM_CFG2_RXWLEN_24B	BIT(3)
#define TAS2562_TDM_CFG2_RXWLEN_32B	(BIT(2) | BIT(3))

#define TAS2562_VSENSE_POWER_EN		BIT(2)
#define TAS2562_ISENSE_POWER_EN		BIT(3)

#define TAS2562_TDM_CFG5_VSNS_EN	BIT(6)
#define TAS2562_TDM_CFG5_VSNS_SLOT_MASK	GENMASK(5, 0)

#define TAS2562_TDM_CFG6_ISNS_EN	BIT(6)
#define TAS2562_TDM_CFG6_ISNS_SLOT_MASK	GENMASK(5, 0)

#endif /* __TAS2562_H__ */
