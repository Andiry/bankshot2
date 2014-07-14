#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>

#include "kernel/bankshot2_cache.h"

int main(int argc, char **argv)
{
	int fd, fd1;
	char *address;

	fd = open("/dev/bankshot2Ctrl0", O_RDWR);

	address = malloc(4096);
	printf("address 0x%lx\n", (unsigned long)address);

	ioctl(fd, BANKSHOT2_IOCTL_GET_DIRTY_INFO, address);

	address[0] = '1';

	ioctl(fd, BANKSHOT2_IOCTL_GET_DIRTY_INFO, address);

	free(address);

	fd1 = open("/mnt/ramdisk/test1", O_RDWR, 0640);

	address = (char *)mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd1, 0);

	printf("mmap address 0x%lx\n", (unsigned long)address);

	ioctl(fd, BANKSHOT2_IOCTL_GET_DIRTY_INFO, address);

	address[0] = '1';

	ioctl(fd, BANKSHOT2_IOCTL_GET_DIRTY_INFO, address);
	munmap(address, 4096);

	close(fd1);
	close(fd);

	return 0;
}
