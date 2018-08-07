/*
 * xrp_hw_hikey: Simple xtensa/arm low-level XRP driver
 *
 * Copyright (c) 2018 Cadence Design Systems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * Alternatively you can use and distribute this file under the terms of
 * the GNU General Public License version 2 or later.
 */

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include "xrp_hw.h"
#include "xrp_hw_simple_dsp_interface.h"

#include <linux/hisi/hisi_rproc.h>

#define DRIVER_NAME "xrp-hw-hikey"

#define XRP_REG_RESET		(0x04)
#define XRP_REG_RUNSTALL	(0x08)

enum xrp_irq_mode {
	XRP_IRQ_NONE,
	XRP_IRQ_LEVEL,
	XRP_IRQ_EDGE,
	XRP_IRQ_MAX,
};

struct ring_buffer {
	uint32_t panic;
	uint32_t read;
	uint32_t write;
	uint32_t size;
	char data[0];
};

struct xrp_hw_hikey {
	struct xvp *xrp;
	struct device *dev;

	phys_addr_t regs_phys;
	struct ring_buffer __iomem *log_rb;
	void __iomem *regs;

	/* how IRQ is used to notify the device of incoming data */
	enum xrp_irq_mode device_irq_mode;
	/* device IRQ# */
	u32 device_irq;
	/* offset of devuce IRQ register in MMIO region (host side) */
	u32 device_irq_host_offset;
	/* how IRQ is used to notify the host of incoming data */
	enum xrp_irq_mode host_irq_mode;
	/*
	 * offset of IRQ register (device side)
	 * bit number
	 */
	u32 host_irq[2];
};

static inline void reg_write32(struct xrp_hw_hikey *hw, unsigned addr, u32 v)
{
	if (hw->regs)
		__raw_writel(v, hw->regs + addr);
}

static void *get_hw_sync_data(void *hw_arg, size_t *sz)
{
	struct xrp_hw_hikey *hw = hw_arg;
	struct xrp_hw_simple_sync_data *hw_sync_data =
		kmalloc(sizeof(*hw_sync_data), GFP_KERNEL);

	if (!hw_sync_data)
		return NULL;

	*hw_sync_data = (struct xrp_hw_simple_sync_data){
		.device_mmio_base = hw->regs_phys,
		.host_irq_mode = hw->host_irq_mode,
		.host_irq_offset = hw->host_irq[0],
		.host_irq_bit = hw->host_irq[1],
		.device_irq_mode = hw->device_irq_mode,
		.device_irq = hw->device_irq,
	};
	*sz = sizeof(*hw_sync_data);
	return hw_sync_data;
}

static int send_cmd_async(struct xrp_hw_hikey *hw, uint32_t mbx, uint32_t cmd)
{
	int ret = RPROC_ASYNC_SEND(mbx, &cmd, 1);
	if (ret != 0) {
		dev_err(hw->dev, "%s: RPROC_ASYNC_SEND ret = %d\n",
			__func__, ret);
	}
	return ret;
}

static int enable(void *hw_arg)
{
	return 0;
}

static void disable(void *hw_arg)
{
}

static void reset(void *hw_arg)
{
}

static void halt(void *hw_arg)
{
	send_cmd_async(hw_arg, HISI_RPROC_LPM3_MBX17,
		       (16 << 16) | (3 << 8) | (1 << 0));
	udelay(100);
}

static void release(void *hw_arg)
{
	send_cmd_async(hw_arg, HISI_RPROC_HIFI_MBX18, 0);
	udelay(100);
}

static void send_irq(void *hw_arg)
{
	struct xrp_hw_hikey *hw = hw_arg;

	switch (hw->device_irq_mode) {
	case XRP_IRQ_EDGE:
	case XRP_IRQ_LEVEL:
		send_cmd_async(hw_arg, HISI_RPROC_HIFI_MBX18, 0);
		break;
	default:
		break;
	}
}

static void ack_irq(void *hw_arg)
{
	struct xrp_hw_hikey *hw = hw_arg;

	if (hw->host_irq_mode == XRP_IRQ_LEVEL)
		reg_write32(hw, hw->host_irq[0], 0);
}

static irqreturn_t irq_handler(int irq, void *dev_id)
{
	struct xrp_hw_hikey *hw = dev_id;
	irqreturn_t ret = xrp_irq_handler(irq, hw->xrp);

	if (ret == IRQ_HANDLED)
		ack_irq(hw);

	return ret;
}

#warning "cache operations are not implemented for this architecture"

static bool panic_check(void *hw_arg)
{
	struct xrp_hw_hikey *hw = hw_arg;
	uint32_t panic;
	uint32_t read;
	uint32_t write;
	uint32_t size;

	if (!hw->log_rb)
		return false;

	panic = __raw_readl(&hw->log_rb->panic);
	read = __raw_readl(&hw->log_rb->read);
	write = __raw_readl(&hw->log_rb->write);
	size = __raw_readl(&hw->log_rb->size);

	if (write < size && read < size) {
		uint32_t tail;
		uint32_t total;
		char *buf = NULL;

		if (read < write) {
			tail = write - read;
			total = tail;
		} else if (read == write) {
			tail = 0;
			total = 0;
		} else {
			tail = size - read;
			total = write + tail;
		}

		if (total)
			buf = kmalloc(total, GFP_KERNEL);

		if (buf) {
			uint32_t off = 0;
			while (off != total) {
				memcpy_fromio(buf + off,
					      hw->log_rb->data + read,
					      tail);
				read = 0;
				off += tail;
				tail = total - tail;
			}
			__raw_writel(write, &hw->log_rb->read);
			dev_info(hw->dev, "<<<\n%.*s\n>>>\n", total, buf);
			kfree(buf);
		} else if (total) {
			dev_err(hw->dev,
				"%s: couldn't allocate memory (%d) to read the dump\n",
				__func__, total);
		}
	}
	if (panic == 0xdeadbabe)
		dev_err(hw->dev, "%s: panic detected\n", __func__);

	return panic == 0xdeadbabe;
}

static const struct xrp_hw_ops hw_ops = {
	.enable = enable,
	.disable = disable,
	.halt = halt,
	.release = release,
	.reset = reset,

	.get_hw_sync_data = get_hw_sync_data,

	.send_irq = send_irq,

	.panic_check = panic_check,
};

static long init_hw(struct platform_device *pdev, struct xrp_hw_hikey *hw,
		    int mem_idx, enum xrp_init_flags *init_flags)
{
	struct resource *mem;
	int irq;
	long ret;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, mem_idx);
	if (mem) {
		hw->log_rb = devm_ioremap_resource(&pdev->dev, mem);
		if (IS_ERR(hw->log_rb)) {
			dev_dbg(&pdev->dev,
				"%s: couldn't ioremap abort/log region: %ld\n",
				__func__, PTR_ERR(hw->log_rb));
			hw->log_rb = NULL;
		} else {
			dev_dbg(&pdev->dev,
				"%s: log ring buffer = %pap, mapped at %p\n",
				__func__, &mem->start, hw->log_rb);
		}
	}

	ret = of_property_read_u32(pdev->dev.of_node,
				   "device-irq",
				   &hw->device_irq);
	if (ret == 0) {
		hw->device_irq_mode = XRP_IRQ_LEVEL;
		dev_dbg(&pdev->dev,
			"%s: device IRQ = %d\n",
			__func__, hw->device_irq);
	} else {
		dev_info(&pdev->dev,
			 "using polling mode on the device side\n");
	}

	ret = of_property_read_u32_array(pdev->dev.of_node, "host-irq",
					 hw->host_irq,
					 ARRAY_SIZE(hw->host_irq));
	if (ret == 0) {
		u32 host_irq_mode;

		ret = of_property_read_u32(pdev->dev.of_node,
					   "host-irq-mode",
					   &host_irq_mode);
		if (host_irq_mode < XRP_IRQ_MAX)
			hw->host_irq_mode = host_irq_mode;
		else
			ret = -ENOENT;
	}

	if (ret == 0 && hw->host_irq_mode != XRP_IRQ_NONE)
		irq = platform_get_irq(pdev, 0);
	else
		irq = -1;

	if (irq >= 0) {
		dev_dbg(&pdev->dev, "%s: host IRQ = %d, ",
			__func__, irq);
		ret = devm_request_irq(&pdev->dev, irq, irq_handler,
				       IRQF_SHARED, pdev->name, hw);
		if (ret < 0) {
			dev_err(&pdev->dev, "request_irq %d failed\n", irq);
			goto err;
		}
		*init_flags |= XRP_INIT_USE_HOST_IRQ;
	} else {
		dev_info(&pdev->dev, "using polling mode on the host side\n");
	}
	ret = 0;
err:
	return ret;
}

typedef long init_function(struct platform_device *pdev,
			   struct xrp_hw_hikey *hw);

static init_function init;
static long init(struct platform_device *pdev, struct xrp_hw_hikey *hw)
{
	long ret;
	enum xrp_init_flags init_flags = 0;

	ret = init_hw(pdev, hw, 0, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init(pdev, init_flags, &hw_ops, hw);
}

static init_function init_v1;
static long init_v1(struct platform_device *pdev, struct xrp_hw_hikey *hw)
{
	long ret;
	enum xrp_init_flags init_flags = 0;

	ret = init_hw(pdev, hw, 1, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init_v1(pdev, init_flags, &hw_ops, hw);
}

static init_function init_cma;
static long init_cma(struct platform_device *pdev, struct xrp_hw_hikey *hw)
{
	long ret;
	enum xrp_init_flags init_flags = 0;

	ret = init_hw(pdev, hw, 0, &init_flags);
	if (ret < 0)
		return ret;

	return xrp_init_cma(pdev, init_flags, &hw_ops, hw);
}

#ifdef CONFIG_OF
static const struct of_device_id xrp_hw_hikey_match[] = {
	{
		.compatible = "cdns,xrp-hw-hikey",
		.data = init,
	}, {
		.compatible = "cdns,xrp-hw-hikey,v1",
		.data = init_v1,
	}, {
		.compatible = "cdns,xrp-hw-hikey,cma",
		.data = init_cma,
	}, {},
};
MODULE_DEVICE_TABLE(of, xrp_hw_hikey_match);
#endif

static int xrp_hw_hikey_probe(struct platform_device *pdev)
{
	struct xrp_hw_hikey *hw =
		devm_kzalloc(&pdev->dev, sizeof(*hw), GFP_KERNEL);
	const struct of_device_id *match;
	init_function *init;
	long ret;

	if (!hw)
		return -ENOMEM;

	match = of_match_device(of_match_ptr(xrp_hw_hikey_match),
				&pdev->dev);
	if (!match)
		return -ENODEV;

	hw->dev = &pdev->dev;
	init = match->data;
	ret = init(pdev, hw);
	if (IS_ERR_VALUE(ret)) {
		xrp_deinit(pdev);
		return ret;
	} else {
		hw->xrp = ERR_PTR(ret);
		return 0;
	}

}

static int xrp_hw_hikey_remove(struct platform_device *pdev)
{
	return xrp_deinit(pdev);
}

static const struct dev_pm_ops xrp_hw_hikey_pm_ops = {
	SET_RUNTIME_PM_OPS(xrp_runtime_suspend,
			   xrp_runtime_resume, NULL)
};

static struct platform_driver xrp_hw_hikey_driver = {
	.probe   = xrp_hw_hikey_probe,
	.remove  = xrp_hw_hikey_remove,
	.driver  = {
		.name = DRIVER_NAME,
		.of_match_table = of_match_ptr(xrp_hw_hikey_match),
		.pm = &xrp_hw_hikey_pm_ops,
	},
};

module_platform_driver(xrp_hw_hikey_driver);

MODULE_AUTHOR("Max Filippov");
MODULE_DESCRIPTION("XRP HiKey: low level device driver for Xtensa Remote Processing");
MODULE_LICENSE("Dual MIT/GPL");
