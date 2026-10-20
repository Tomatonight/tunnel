# Build against the target kernel's configured headers, not the host compiler ABI.
ifneq ($(KERNELRELEASE),)
obj-m += tunnel_kmod.o
# Probe the target headers rather than assume a distro did not backport APIs.
ccflags-y += $(shell grep -q 'u16 ipcb_flags' $(srctree)/include/net/udp_tunnel.h && echo -DTK_UDP_XMIT_FLAGS)
ccflags-y += $(shell grep -q '^void udp_tunnel6_xmit_skb' $(srctree)/include/net/udp_tunnel.h && echo -DTK_UDP6_XMIT_VOID)
ccflags-y += $(shell grep -q 'setup_udp_tunnel_sock.*struct sock \*' $(srctree)/include/net/udp_tunnel.h && echo -DTK_SETUP_USES_SK)
ccflags-y += $(shell grep -q 'netns_immutable:1' $(srctree)/include/linux/netdevice.h && echo -DTK_NETNS_IMMUTABLE)
else
KDIR ?= /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
install:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install
	depmod -a $$(cat $(KDIR)/include/config/kernel.release)
.PHONY: all clean install
endif
