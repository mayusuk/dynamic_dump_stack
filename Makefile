PWD:= $(shell pwd)
ROOT=/opt/iot-devkit/1.7.2/sysroots

KDIR:=$(ROOT)/i586-poky-linux/usr/src/kernel
SROOT:=$(ROOT)/i586-poky-linux/

CFLAGS+ = -Wall -g
CC = i586-poky-linux-gcc
ARCH = x86
CROSS_COMPILE = i586-poky-linux-
APP_INSDUMP = insdump_tester
APP_RMSDUMP = rmdump_tester
obj-m += dump_stack_dev.o

all:
	$(CC) -Wall -g -o $(APP_INSDUMP) syscall_test.c --sysroot=$(SROOT) -lpthread -Wall
	$(CC) -Wall -g -o $(APP_RMSDUMP) syscall_test_rmdump.c --sysroot=$(SROOT) -lpthread -Wall
clean:
	make ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(SROOT)/usr/src/kernel M=$(PWD) clean
