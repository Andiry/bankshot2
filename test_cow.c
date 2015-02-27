#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <time.h>

#define PMFS_COW_WRITE	0xBCD00012
#define	SIZE	(4096* 4)

struct write_request {
	char* buf;
	loff_t offset;
	size_t len;
};

static void compare(char *buf, char *buf1, size_t size)
{
	int i;

	for (i = 0; i < size; i+= 4096) {
		if (buf[i] != buf1[i]) {
			printf("ERROR: %d, %c, %c\n",
				i, buf[i], buf1[i]);
		}
	}
}

int main(int argc, char *argv[])
{
	int fd1;
	struct write_request packet;
	off_t offset;
	size_t len, ret;
	char c = 'c';
	char* buf = malloc(SIZE);
	char* buf1 = malloc(SIZE);
	char *tmp;
	char *buf2 = malloc(4096 * 3);
	int i;

	fd1 = open("/mnt/ramdisk/test1", O_RDWR | O_CREAT, 0640);
	offset = 0;
	len = SIZE;
	tmp = buf;
	for (i = 0; i < SIZE / 4096; i++) {
		memset(tmp, c, 4096);
		tmp += 4096;
		c++;
	}
	packet.offset = offset;
	packet.len = len;
	packet.buf = buf;

	ioctl(fd1, PMFS_COW_WRITE, &packet);
	ret = pread(fd1, buf1, SIZE, 0);

	compare(buf, buf1, SIZE);
	printf("pread: %lu\n", ret);

	offset = 1219;
	len = 9600;
	memset(buf2, 'y', len);
	memset(buf + offset, 'y', len);
	packet.offset = offset;
	packet.len = len;
	packet.buf = buf2;

	ioctl(fd1, PMFS_COW_WRITE, &packet);
	ret = pread(fd1, buf1, SIZE, 0);

	compare(buf, buf1, SIZE);
	printf("pread: %lu\n", ret);

	close(fd1);
	free(buf);
	free(buf1);
	free(buf2);

	return 0;
}
