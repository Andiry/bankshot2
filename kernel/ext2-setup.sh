#!/bin/sh

umount /mnt/ramdisk
mkfs.ext2 -b 4096 /dev/ram1

sleep 1
echo "Mount to /mnt/ramdisk.."
mount /dev/ram1 /mnt/ramdisk

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
