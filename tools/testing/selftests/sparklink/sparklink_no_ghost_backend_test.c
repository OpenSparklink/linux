// SPDX-License-Identifier: GPL-2.0-only
/* Empty-USB scratch VM only; no real bus/device I/O. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>
#include "sparklink_ioctl.h"

static int empty_registry(int fd)
{
	unsigned short mask = 0xffff;
	struct sle_controller_snapshot snapshot = { .version = 1 };
	if (ioctl(fd, SL_IOCTL_DEV_LIST, &mask) || mask)
		return -1;
	errno = 0;
	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &snapshot) != -1 || errno != ENODEV)
		return -1;
	return 0;
}

int main(void)
{
	char vendor[64] = {0}, label[32] = {0};
	int fd = open("/sys/class/dmi/id/sys_vendor", O_RDONLY);
	if (fd < 0 || read(fd, vendor, sizeof(vendor) - 1) <= 0) return 1;
	close(fd);
	if (geteuid() || strcmp(vendor, "QEMU\n") || access("/scratch-root-uuid", R_OK)) return 1;
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) && errno != EBUSY) return 1;
	fd = open("/dev/sparklink", O_RDWR | O_CLOEXEC);
	if (fd < 0 || empty_registry(fd)) return 1;
	const char *values[] = {"uart", "1", "spi", "2", "usb", "4", "none", "0", "i2c"};
	for (unsigned int i = 0; i < sizeof(values)/sizeof(values[0]); i++) {
		int cfg = open("/sys/kernel/config/sparklink/controller_type", O_WRONLY | O_CLOEXEC);
		if (cfg < 0) return 1;
		errno = 0;
		ssize_t result = write(cfg, values[i], strlen(values[i]));
		int error = errno;
		close(cfg);
		if (i < 6 && (result != -1 || error != EOPNOTSUPP)) return 1;
		if ((i == 6 || i == 7) && result != (ssize_t)strlen(values[i])) return 1;
		if (i == 8 && (result != -1 || error != EINVAL)) return 1;
		cfg = open("/sys/kernel/config/sparklink/controller_type", O_RDONLY | O_CLOEXEC);
		memset(label, 0, sizeof(label));
		if (cfg < 0 || read(cfg, label, sizeof(label) - 1) <= 0) return 1;
		close(cfg);
		if (strcmp(label, "none\n") || empty_registry(fd)) return 1;
	}
	close(fd);
	puts("SPARKLINK_NO_GHOST_BACKEND_PASS selectors=9 registered=0 snapshot=ENODEV");
	return 0;
}
