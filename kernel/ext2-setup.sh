#!/bin/sh

umount /mnt/ramdisk1
mkfs.ext2 -b 4096 /dev/ram1

sleep 1
echo "Mount to /mnt/ramdisk1.."
mount -o noatime /dev/ram1 /mnt/ramdisk1

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
