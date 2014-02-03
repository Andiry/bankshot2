#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

int main(void)
{
	int fd;
	int a = 3, b = 4;

	fd = open("/dev/bankshotCtrl0", O_RDWR);
	ioctl(fd, 0xBCD00000, &a);

	close(fd);

	fd = open("/dev/bankshotCtrl1", O_RDWR);
	ioctl(fd, 0xBCD00000, &b);

	close(fd);
	return 0;
}
