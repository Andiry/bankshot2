obj-m += bankshot2.o

bankshot2-y :=bankshot2_init.o bankshot2_char.o bankshot2_cache.o \
		bankshot2_io.o bankshot2_block.o bankshot2_mem.o \
		bankshot2_inode.o bankshot2_xip.o bankshot2_mmap.o \
		bankshot2_super.o bankshot2_extent.o bankshot2_stats.o

all:
	make -C /media/root/New_Volume1/Linux-pmfs M=`pwd`

running:
	make -C /media/root/External-Linux/Linux-pmfs M=`pwd`
	
clean:
	rm -rf *.o *.mod.c modules.* Module.* bankshot2.ko
