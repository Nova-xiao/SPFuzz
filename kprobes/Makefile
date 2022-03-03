#obj-m += kernels.o
#obj-m += globals.o
#obj-m += do.o
# obj-m += globals.o
obj-m += modules.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -o user.o user.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm user.o
