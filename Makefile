obj-m += krdma_test.o
krdma_test-y := krdma_test.o getopt.o

KERNELDIR:=/lib/modules/5.0.5/build
PWD:=$(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean