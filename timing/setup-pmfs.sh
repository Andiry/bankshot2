#!/bin/sh

umount /mnt/ramdisk
rmmod pmfs
modprobe pmfs measure_timing=1

sleep 1

mount -t pmfs -o physaddr=0x100000000,init=8G none /mnt/ramdisk

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
