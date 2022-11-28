obj-m += ko_test.o

KDIR =/home/chexijia/CCS_hw1/linux-5.4.98

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order