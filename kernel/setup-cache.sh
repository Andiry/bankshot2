#!/bin/sh

umount /mnt/ramdisk
sleep 1
rmmod bankshot2

sleep 1

echo "load bankshot2 kernel module..."
insmod bankshot2.ko phys_addr=0x100000000 cache_size=0x4000000 backing_dev_name=/dev/memuram0
#mount -t pmfs -o physaddr=0x100000000,init=2G,backing_dev=/dev/ram0 none /mnt/ramdisk

sleep 1
echo "Make XFS on bankshot2 block device.."
mkfs.xfs /dev/bankshot2Block0

sleep 1
echo "Mount to /mnt/ramdisk.."
mount /dev/bankshot2Block0 /mnt/ramdisk

#cp test1 /mnt/ramdisk/
#dd if=/dev/zero of=/mnt/ramdisk/test1 bs=1M count=1024 oflag=direct
