obj-m += antitest.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	@if [ ! -d $(KDIR) ]; then echo "Kernel headers not found at $(KDIR). Install linux-headers-$(shell uname -r)"; exit 1; fi
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
