obj-m +=oslab.o

KDIR = /usr/src/linux-headers-4.10.0-28-generic

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order