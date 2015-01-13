#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>

#include "kernel/bankshot2_cache.h"
#include "ioctl.h"

struct extent_entry {
	off_t offset;
	size_t length;
	int dirty;
	unsigned long mmap_addr;
};

struct sync_range {
	off_t offset;
	size_t length;
};

int main(void)
{
	int fd1;
	struct sync_range packet;
	off_t offset = 1000;
	size_t len = 2000;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	packet.offset = offset;
	packet.length = len;

	ioctl(fd1, FS_PMFS_FSYNC, &packet);

	close(fd1);

	return 0;
}
