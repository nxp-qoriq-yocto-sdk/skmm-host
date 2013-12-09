# Copyright 2013 Freescale Semiconductor, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#
#
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Freescale Semiconductor nor the
# names of its contributors may be used to endorse or promote products
# derived from this software without specific prior written permission.
#
#
# ALTERNATIVELY, this software may be distributed under the terms of the
# GNU General Public License ("GPL") as published by the Free Software
# Foundation, either version 2 of that License or (at your option) any
# later version.
#
# THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE)ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
TOPDIR ?= $(shell pwd)
export TOPDIR
include $(TOPDIR)/config.mk

ifeq ("$(ARCH)","powerpc")
P4080_BUILD=y
endif

ifeq ("$(ARCH)","x86")
X86_BUILD=y
endif

ifeq ($(HIGH_PERF_MODE),y)
EXTRA_CFLAGS += -DHIGH_PERF
endif

#Specifies the endianness
BE=1
LE=2

ifeq ($(P4080_BUILD),y)
DEVICE_ENDIAN=$(LE)
HOST_ENDIAN=$(BE)
else
DEVICE_ENDIAN=$(BE)
HOST_ENDIAN=$(LE)
endif

# Below code sets the compile time flags
EXTRA_CFLAGS += -DBIG_ENDIAN=$(BE) -DLITTLE_ENDIAN=$(LE) -g3

ifeq ($(DEVICE_ENDIAN),$(BE))
EXTRA_CFLAGS += -DDEVICE_ENDIAN=$(BE)
else
EXTRA_CFLAGS += -DDEVICE_ENDIAN=$(LE)
endif

ifeq ($(P4080_BUILD),y)
EXTRA_CFLAGS += -DHOST_ENDIAN=$(BE)
else
EXTRA_CFLAGS += -DHOST_ENDIAN=$(LE)
endif

ifeq ($(P4080_BUILD),y)
EXTRA_CFLAGS += -DP4080_BUILD
endif

ifeq ($(X86_BUILD),y)
EXTRA_CFLAGS += -DX86_BUILD
KERNEL_DIR ?=/lib/modules/$(shell uname -r)/build
endif

ifeq ($(P4080_EP),y)
EXTRA_CFLAGS += -DP4080_EP
endif

ifeq ($(C293_EP),y)
EXTRA_CFLAGS += -DC293_EP
endif

ifeq ($(DEBUG_PRINT),y)
EXTRA_CFLAGS += -DDEV_PRINT_DBG -DPRINT_DEBUG
endif

ifeq ($(ERROR_PRINT),y)
EXTRA_CFLAGS += -DDEV_PRINT_ERR -DPRINT_ERROR
endif

ifeq ($(INFO_PRINT),y)
EXTRA_CFLAGS += -DPRINT_INFO
endif

EXTRA_CFLAGS += -DDEV_PHYS_ADDR_64BIT -DDEV_VIRT_ADDR_32BIT

ifeq ($(VIRTIO_C2X0),y)
EXTRA_CFLAGS += -DVIRTIO_C2X0
endif

ifeq ($(CONFIG_FSL_C2X0_HASH_OFFLOAD),y)
EXTRA_CFLAGS += -DHASH_OFFLOAD
endif

ifeq ($(CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD),y)
EXTRA_CFLAGS += -DSYMMETRIC_OFFLOAD
endif

ifeq ($(RNG_OFFLOAD),y)
EXTRA_CFLAGS += -DRNG_OFFLOAD
endif

ifeq ($(USE_HOST_DMA), y)
EXTRA_CFLAGS += -DUSE_HOST_DMA
endif

EXTRA_CFLAGS += -I$(TOPDIR)/host_driver -I$(TOPDIR)/algs -I$(TOPDIR)/crypto_dev -I$(TOPDIR)/dcl -I$(TOPDIR)/test

DRIVER_PATH = $(TOPDIR)
DRIVER_KOBJ = "fsl_crypto_offload_drv"
RSA_TEST_KOBJ = "rsa_test"
DSA_TEST_KOBJ = "dsa_test"
ECDSA_TEST_KOBJ = "ecdsa_test"
DH_TEST_KOBJ = "dh_test"
ECDH_TEST_KOBJ = "ecdh_test"
PCI_DMA_TEST_KOBJ = "pci_dma_test"

CONFIG_FSL_C2X0_CRYPTO_DRV=m

obj-$(CONFIG_FSL_C2X0_CRYPTO_DRV) = $(DRIVER_KOBJ).o
obj-m += $(PCI_DMA_TEST_KOBJ).o

$(DRIVER_KOBJ)-objs := host_driver/fsl_c2x0_driver.o
$(DRIVER_KOBJ)-objs += host_driver/fsl_c2x0_crypto_layer.o
$(DRIVER_KOBJ)-objs += host_driver/memmgr.o
$(DRIVER_KOBJ)-objs += host_driver/command.o
$(DRIVER_KOBJ)-objs += host_driver/sysfs.o
ifeq ($(USE_HOST_DMA),y)
$(DRIVER_KOBJ)-objs += host_driver/dma.o
endif
$(DRIVER_KOBJ)-objs += algs/algs.o
$(DRIVER_KOBJ)-objs += algs/abs_req.o
$(DRIVER_KOBJ)-objs += algs/rsa.o
$(DRIVER_KOBJ)-objs += algs/dsa.o
$(DRIVER_KOBJ)-objs += algs/dh.o
$(DRIVER_KOBJ)-objs += algs/desc_cnstr.o
$(DRIVER_KOBJ)-objs += algs/rng_init.o
$(DRIVER_KOBJ)-objs += crypto_dev/algs_reg.o
ifeq ($(CONFIG_FSL_C2X0_HASH_OFFLOAD),y)
$(DRIVER_KOBJ)-objs += algs/hash.o
endif
ifeq ($(CONFIG_FSL_C2X0_SYMMETRIC_OFFLOAD),y)
$(DRIVER_KOBJ)-objs += algs/symmetric.o
endif
ifeq ($(RNG_OFFLOAD),y)
$(DRIVER_KOBJ)-objs += algs/rng.o
endif

ifeq ($(VIRTIO_C2X0),n)
$(DRIVER_KOBJ)-objs += test/rsa_test.o
$(DRIVER_KOBJ)-objs += test/dsa_test.o
$(DRIVER_KOBJ)-objs += test/ecdsa_test.o
$(DRIVER_KOBJ)-objs += test/ecp_test.o
$(DRIVER_KOBJ)-objs += test/ecpbn_test.o
$(DRIVER_KOBJ)-objs += test/dh_test.o
$(DRIVER_KOBJ)-objs += test/ecdh_test.o
$(DRIVER_KOBJ)-objs += test/ecdh_keygen_test.o
$(DRIVER_KOBJ)-objs += test/test.o
endif

$(PCI_DMA_TEST_KOBJ)-objs := pci_dma_test/pci_dma_dev.o
$(PCI_DMA_TEST_KOBJ)-objs += pci_dma_test/pci_dma_sys.o
$(PCI_DMA_TEST_KOBJ)-objs += pci_dma_test/pci_dma_test.o

.PHONY: build

build:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` modules
	$(CROSS_COMPILE)gcc  -Wall perf/mini_calc/mini_calc.c -o mini_calc -static

modules_install:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` modules_install
	@install -D crypto.cfg $(PREFIX)/etc/skmm/skmm_crypto.cfg

clean:
	make -C $(KERNEL_DIR) SUBDIRS=`pwd` clean

dist: clean
