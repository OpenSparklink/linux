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
	unsigned short active = 0;
	short selected = 0;
	struct sle_controller_snapshot snapshot = { .version = 1 };
	if (ioctl(fd, SL_IOCTL_DEV_LIST, &mask) || mask)
		return -1;
	if (ioctl(fd, SL_IOCTL_DEV_GET_ACTIVE, &active) || active != 0xffff)
		return -1;
	errno = 0;
	if (ioctl(fd, SL_IOCTL_DEV_SELECT, &selected) != -1 || errno != ENODEV)
		return -1;
	errno = 0;
	/* No per-fd affinity is an invalid request, distinct from a retired id. */
	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &snapshot) != -1 || errno != EINVAL)
		return -1;
	return 0;
}

int main(void)
{
	char vendor[64] = {0};
	int fd = open("/sys/class/dmi/id/sys_vendor", O_RDONLY);
	if (fd < 0 || read(fd, vendor, sizeof(vendor) - 1) <= 0) return 1;
	close(fd);
	if (geteuid() || strcmp(vendor, "QEMU\n") || access("/scratch-root-uuid", R_OK)) return 1;
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) && errno != EBUSY) return 1;
	fd = open("/dev/sparklink", O_RDWR | O_CLOEXEC);
	if (fd < 0 || empty_registry(fd)) return 1;
    const char *names[] = {"max_connections", "adv_interval_ms", "scan_window_ms", "power_mode", "controller_type"};
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        char path[128]; snprintf(path, sizeof(path), "/sys/kernel/config/sparklink/%s", names[i]);
        errno = 0;
        if (open(path, O_RDWR | O_CLOEXEC) != -1 || errno != ENOENT || empty_registry(fd)) return 1;
    }
	close(fd);
	puts("SPARKLINK_NO_GHOST_BACKEND_PASS removed_attrs=5 registered=0 select=ENODEV unbound_snapshot=EINVAL");
	return 0;
}
