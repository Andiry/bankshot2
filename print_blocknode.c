#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>

#define PMFS_PRINT_LOG_BLOCKNODE	0xBCD00014

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

struct write_request {
	char* buf;
	loff_t offset;
	size_t len;
};

int main(int argc, char *argv[])
{
	int fd1;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);

	ioctl(fd1, PMFS_PRINT_LOG_BLOCKNODE, &fd1);

	close(fd1);

	return 0;
}
