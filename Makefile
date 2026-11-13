KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += alp.o cxd2878.o m88rs6060.o tbs5530.o it930x.o

ccflags-y += -I$(src) -DCONFIG_DVB_CXD2878=1

# SYS_ATSC3 is not in mainline <linux/dvb/frontend.h>. Use the kernel's own
# enum value when its headers have one (patched kernels), otherwise fall
# back to 35, the value upstream cxd28xx uses on stock kernels.
ifneq ($(srctree),)
ifeq ($(shell grep -qw SYS_ATSC3 $(srctree)/include/uapi/linux/dvb/frontend.h 2>/dev/null && echo y),)
ccflags-y += -DCXD28XX_SYS_ATSC3_FALLBACK=35
endif
endif

# Userspace tools must agree with the module: same rule against the libc
# copy of the UAPI headers.
UAPI_FE ?= /usr/include/linux/dvb/frontend.h
UTILS_ATSC3 := $(if $(shell grep -qw SYS_ATSC3 $(UAPI_FE) 2>/dev/null && echo y),,-DSYS_ATSC3=35)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

utils:
	$(CC) -O2 -Wall $(UTILS_ATSC3) -o atsc3-zap utils/atsc3-zap.c
	$(CC) -O2 -Wall $(UTILS_ATSC3) -o alp-capture utils/alp-capture.c

udev:
	install -m 644 99-alpraw.rules /etc/udev/rules.d/99-alpraw.rules
	udevadm control --reload
	udevadm trigger --subsystem-match=misc

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f atsc3-zap alp-capture

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

.PHONY: all utils udev clean install
