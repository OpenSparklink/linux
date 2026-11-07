// SPDX-License-Identifier: GPL-2.0-only
/* Minimal PID 1 for the WS73 USB boot gate; no busybox or guest disk required. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>

static int expected_count(void)
{
	char buf[4096], *option;
	FILE *file = fopen("/proc/cmdline", "r");
	int expected = 0;

	if (!file)
		return 0;
	if (fgets(buf, sizeof(buf), file)) {
		option = strstr(buf, "ws73.expected=");
		if (option)
			expected = atoi(option + strlen("ws73.expected="));
	}
	fclose(file);
	return expected;
}

static int runtime_count(void)
{
	const char *base = "/sys/bus/usb/drivers/sparklink_ws73_usb";
	char path[512], state[64];
	struct dirent *entry;
	DIR *dir = opendir(base);
	int count = 0;

	if (!dir)
		return 0;
	while ((entry = readdir(dir))) {
		FILE *file;

		if (!strchr(entry->d_name, ':'))
			continue;
		snprintf(path, sizeof(path), "%s/%s/runtime_transport", base, entry->d_name);
		file = fopen(path, "r");
		if (!file)
			continue;
		if (fgets(state, sizeof(state), file) &&
		    !strcmp(state, "1\n"))
			count++;
		fclose(file);
	}
	closedir(dir);
	return count;
}

int main(void)
{
	int expected, count = 0, i, console;

	/* The root archive needs no privileged mknod: devtmpfs supplies console. */
	(void)mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	console = open("/dev/console", O_RDWR);
	if (console >= 0) {
		for (i = 0; i < 3; i++)
			(void)dup2(console, i);
		if (console > 2)
			close(console);
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	if (mount("proc", "/proc", "proc", 0, NULL) ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL)) {
		printf("WS73_BOOT_GATE: FAIL (mount: %s)\n", strerror(errno));
		goto poweroff;
	}
	expected = expected_count();
	if (expected <= 0 || expected > 4) {
		puts("WS73_BOOT_GATE: FAIL (expected device count must be 1..4)");
		goto poweroff;
	}
	for (i = 0; i < 80; i++) {
		count = runtime_count();
		if (count == expected)
			break;
		sleep(1);
	}
	printf("WS73_BOOT_GATE: %s (runtime interfaces %d/%d; SLE not tested)\n",
	       count == expected ? "PASS" : "FAIL", count, expected);
poweroff:
	sync();
	reboot(RB_POWER_OFF);
	for (;;)
		pause();
}
