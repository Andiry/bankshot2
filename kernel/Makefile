obj-m += bankshot2.o

bankshot2-y :=bankshot2_core.o bankshot2_char.o bankshot2_cache.o

all:
	make -C /media/root/e755aa6d-e75c-46b1-a871-d4c7a5587972/usr/src/linux M=`pwd`

running:
	make -C /media/root/5afd72e1-c6c2-41f0-9606-8cd62259c55b/Linux-pmfs M=`pwd`
	
clean:
	rm -rf *.o *.mod.c modules.* Module.* bankshot2.ko
