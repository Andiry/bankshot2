#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>

#define PMFS_COW_WRITE	0xBCD00012

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
	off_t offset;
	size_t size, ret;
	char* buf;
//	int i;

	if (argc != 3) {
		printf("Usage: ./test_write offset size\n");
		return 0;
	}

	offset = atol(argv[1]);
	size = atol(argv[2]);
	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);

	buf = malloc(size);
	memset(buf, '0', size);
//	for (i = 0; i < 135; i++)
	ret = pwrite(fd1, buf, size, offset);

	close(fd1);
	free(buf);

	return 0;
}
