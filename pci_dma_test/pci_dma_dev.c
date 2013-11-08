/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Author: Minghuan Lian <Minghuan.Lian@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/of_device.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/module.h>

#include "pci_dma_test.h"

static const char *driver_name = "FSL-PCIDMA-driver";

#define PCI_DEVICE_ID_T4240 0x0440

LIST_HEAD(pcidma_list);

static unsigned int num_vfs;
module_param(num_vfs, uint, S_IRUGO);
MODULE_PARM_DESC(num_vfs, "Number of PCI VFs to initialize");

static void pcidma_dev_release(struct device *dev)
{
	/* nothing to do */
}

static void pcidma_class_release(struct class *cls)
{
	/* nothing to do */
}

static struct class pcidma_class = {
	.name = "pcidma",
	.dev_attrs = pcidma_attrs,
	.dev_release = pcidma_dev_release,
	.class_release = pcidma_class_release,
};

static int pcidma_class_init(void)
{
	int ret;

	ret = class_register(&pcidma_class);
	if (ret) {
		pr_err("class_register failed for pcidma\n");
		return -EINVAL;
	}

	return 0;
}

static void pcidma_class_free(void)
{
	class_unregister(&pcidma_class);
}

static int pcidma_vf_init(struct fsl_pcidma_dev *pcidma)
{
	struct pci_dev *pdev = pcidma->pdev;
	struct vf_info *vf;
	int pos;

	if (!pci_is_pcie(pdev))
		return -ENODEV;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	vf = kzalloc(sizeof(*vf), GFP_KERNEL);
	if (!vf)
		return 0;
	pcidma->vf = vf;

	pci_read_config_word(pdev, pos + PCI_SRIOV_TOTAL_VF, &vf->total);
	if (!vf->total)
		return 0;

	if (num_vfs > vf->total)
		num_vfs = vf->total;

	vf->availbe_num = num_vfs;

	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_OFFSET, &vf->offset);
	pci_read_config_word(pdev, pos + PCI_SRIOV_VF_STRIDE, &vf->stride);

	pci_enable_sriov(pdev, vf->availbe_num);

	dev_dbg(&pdev->dev, "offset is %d  stride is %d %d VFs allocated\n",
		vf->offset, vf->stride, vf->availbe_num);

	return 0;
}

static void pcidma_dev_free(struct fsl_pcidma_dev *pcidma)
{
	if (!pcidma)
		return;

	if (pcidma->config)
		pci_iounmap(pcidma->pdev, pcidma->config);

	pcidma_test_info_free(pcidma->test_info);

	device_unregister(&pcidma->dev);

	/* Delete the device from list */
	if (pcidma->node.next)
		list_del(&pcidma->node);

	pci_set_drvdata(pcidma->pdev, NULL);
	kfree(pcidma);
}

static struct fsl_pcidma_dev *pcidma_dev_init(struct pci_dev *pdev)
{
	struct fsl_pcidma_dev *pcidma;
	static int pcidma_num;
	int i;

	pcidma = kzalloc(sizeof(*pcidma), GFP_KERNEL);
	if (!pcidma) {
		dev_err(&pdev->dev, "failed to kzalloc for pcidma\n");
		return NULL;
	}

	pcidma->dev.parent = &pdev->dev;
	pcidma->pdev = pdev;
	pci_set_drvdata(pdev, pcidma);

	pcidma->dev.bus = NULL;
	pcidma->dev.class = &pcidma_class;

	dev_set_name(&pcidma->dev, "pcidma%d", pcidma_num++);

	if (device_register(&pcidma->dev)) {
		dev_err(&pdev->dev, "failed to register pcidma\n");
		kfree(pcidma);
		return NULL;
	}

	/* Get the BAR resources and remap them into the driver memory */
	for (i = 0; i < PCI_MAX_BAR; i++) {
		/* Read the hardware address */
		pcidma->bars[i].phy_addr = pci_resource_start(pdev, i);
		pcidma->bars[i].size = pci_resource_len(pdev, i);
		dev_dbg(&pdev->dev, "BAR:%d  addr:0x%llx len:0x%llx\n",
			 i, pcidma->bars[i].phy_addr,
			 (u64)pcidma->bars[i].size);
	}

	/* Map the MEM to the kernel address space */
	pcidma->config = pci_iomap(pdev, PCI_CONFIG_BAR, 0);
	if (!pcidma->config) {
		dev_err(&pdev->dev,
			"%s failed to Map config space\n", pci_name(pdev));
		goto _err;
	}

	/* Init VF */
	pcidma_vf_init(pcidma);

	pcidma->test_info = pcidma_test_info_init(pcidma);
	if (!pcidma->test_info)
		goto _err;

	dev_info(&pdev->dev, "initialized and associated with %s\n",
		 dev_name(&pcidma->dev));

	list_add_tail(&pcidma->node, &pcidma_list);
	return pcidma;

_err:
	pcidma_dev_free(pcidma);
	return NULL;
}


static int fsl_pcidma_dev_probe(struct pci_dev *pdev,
				const struct pci_device_id *id)
{
	int err;
	struct fsl_pcidma_dev *pcidma;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "failed to enable\n");
		return err;
	}

	err = pci_request_regions(pdev, driver_name);
	if (err) {
		dev_err(&pdev->dev, "failed to request pci regions\n");
		goto _err;
	}

	pci_set_master(pdev);

	err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		err = dma_set_mask(&pdev->dev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Could not set PCI DMA Mask\n");
			goto _err;
		}
	}

	/* Allocate memory for the new PCI device data structure */
	pcidma = pcidma_dev_init(pdev);
	if (!pcidma) {
		err = -EINVAL;
		goto _err;
	}

	return 0;

_err:
	pci_disable_device(pdev);
	return err;
}

static void fsl_pcidma_dev_remove(struct pci_dev *pdev)
{
	struct fsl_pcidma_dev *pcidma = pci_get_drvdata(pdev);

	if (!pcidma)
		return;

	pcidma_dev_free(pcidma);

	pci_release_regions(pdev);

	pci_disable_device(pdev);
}

#define PCI_DEVICE_ID_T2080 0x0830
#define PCI_DEVICE_ID_T2080_VF_PF0 0
#define PCI_DEVICE_ID_T2080_VF_PF1 0x1957

static DEFINE_PCI_DEVICE_TABLE(fsl_pci_dev_ids) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T4240) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P4080) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P5020) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P5020E) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_P3041) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, 0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, 0x13) },
	/* For T2080 */
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T2080) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T2080_VF_PF0) },
	{ PCI_DEVICE(PCI_VENDOR_ID_FREESCALE, PCI_DEVICE_ID_T2080_VF_PF1) },
	{ 0 },
};

static struct pci_driver fsl_pcidma_dev_driver = {
	.name		= "FSL-PCIDMA-Driver",
	.id_table	= fsl_pci_dev_ids,
	.probe		= fsl_pcidma_dev_probe,
	.remove		= fsl_pcidma_dev_remove
};

static int __init fsl_pcidma_dev_init(void)
{
	int err = 0;

	pr_info("FSL PCI DMA Test Driver.\n");

	err = pcidma_class_init();
	if (err)
		return err;

	err = pci_register_driver(&fsl_pcidma_dev_driver);
	if (err) {
		pr_err("%s:%d pci_register_driver() failed\n",
			__func__, __LINE__);
		pcidma_class_free();
		return err;
	}

	return 0;
}

static void __exit fsl_pcidma_dev_exit(void)
{
	pr_err("Exit from FSL PCI DMA driver\n");
	pci_unregister_driver(&fsl_pcidma_dev_driver);
	pcidma_class_free();
	return;
}

module_init(fsl_pcidma_dev_init);
module_exit(fsl_pcidma_dev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Minghuan Lian <Minghuan.Lian@freescale.com>");
MODULE_DESCRIPTION("Freescale PCI DMA Test Driver");
MODULE_VERSION("Version 1.0.0");
