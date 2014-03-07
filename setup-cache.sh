#!/bin/sh

rmmod bankshot2

sleep 1

insmod kernel/bankshot2.ko phys_addr=0x100000000 cache_size=0x1000000
#mount -t pmfs -o physaddr=0x100000000,init=2G,backing_dev=/dev/ram0 none /mnt/ramdisk

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
