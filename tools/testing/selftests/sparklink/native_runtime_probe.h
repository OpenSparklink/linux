// SPDX-License-Identifier: GPL-2.0-only
/* Current Native syscall helpers for isolated open/usercopy probes. Synthetic
 * USB controller; not a Host, protocol Engine or physical/RF qualification. */
#ifndef SPARKLINK_NATIVE_RUNTIME_PROBE_H
#define SPARKLINK_NATIVE_RUNTIME_PROBE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
#include "retired_ioctl_numbers.h"
static int failed;
static int fail(const char *why)
{
	fprintf(stderr, "NATIVE_FAILURE: %s errno=%d\n", why, errno);
	failed = 1;
	return -1;
}

static double now(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t))
		exit(1);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static int mask_wait(int fd, uint16_t expected)
{
	double deadline = now() + 10;
	while (now() < deadline) {
		uint16_t mask = 0;
		if (ioctl(fd, SL_IOCTL_DEV_LIST, &mask))
			return fail("list adapters");
		if (mask == expected)
			return 0;
		usleep(10000);
	}
	return fail("registration/removal deadline");
}

static int native_identity(unsigned int id, unsigned long long *generation)
{
	DIR *directory = opendir("/sys/bus/usb/drivers/sparklink_ws73_usb");
	struct dirent *entry;
	int found = 0;

	if (!directory)
		return -1;
	while ((entry = readdir(directory))) {
		char path[512], stage[64];
		int index = -1;
		unsigned int streaming, broken;
		unsigned long long gen;
		FILE *file;

		if (!strchr(entry->d_name, ':'))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/drivers/sparklink_ws73_usb/%s/native_runtime", entry->d_name);
		file = fopen(path, "r");
		if (!file)
			continue;
		int parsed = fscanf(file, "id=%d generation=%llu streaming=%u broken=%u", &index, &gen, &streaming, &broken);
		fclose(file);
		if (parsed != 4 || index != (int)id)
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/drivers/sparklink_ws73_usb/%s/boot_stage", entry->d_name);
		file = fopen(path, "r");
		if (!file)
			continue;
		int read = fscanf(file, "%63s", stage);
		fclose(file);
		if (read != 1 || (strcmp(stage, "native-runtime-setup") &&
				 strcmp(stage, "native-runtime-ready")) || !streaming || broken || !gen)
			continue;
		*generation = gen;
		found++;
	}
	closedir(directory);
	return found == 1 ? 0 : -1;
}

static int bind_owner(unsigned int id, struct sci_dev_info *info, unsigned long long *generation)
{
	uint16_t selected = id;
	double deadline = now() + 10;
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);

	if (fd < 0)
		return fail("open adapter fd");
	while (now() < deadline) {
		if (!ioctl(fd, SL_IOCTL_DEV_SELECT, &selected) && !ioctl(fd, SL_IOCTL_DEV_INFO, info)) {
			if (info->index != id)
				break;
			if (!native_identity(id, generation))
				return fd;
			usleep(10000);
			continue;
		}
		if (errno != ENODEV)
			break;
		usleep(10000);
	}
	close(fd);
	return fail("bind native Runtime");
}

static int management_mode(int fd, unsigned long long generation, unsigned mode)
{
    struct sle_management_query q = { .version = 1, .generation = generation };
    if (ioctl(fd, SL_IOCTL_MANAGEMENT_QUERY, &q)) return fail("management status");
    if (q.flags == 1 && q.mode == mode) return 0;
    if (q.flags == 1) {
        struct sle_management_request release = { .version = 1, .generation = q.generation,
            .lease = q.lease, .mode = q.mode };
        if (ioctl(fd, SL_IOCTL_MANAGEMENT_RELEASE, &release)) return fail("management release");
    }
    double deadline = now() + 7;
    do {
        q = (struct sle_management_query){ .version = 1, .generation = generation };
        if (ioctl(fd, SL_IOCTL_MANAGEMENT_QUERY, &q)) return fail("management revocation status");
        if (q.state == SLE_MANAGEMENT_FREE) {
            struct sle_management_request acquire = { .version = 1, .generation = q.generation, .mode = mode };
            if (ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &acquire) || !acquire.lease)
                return fail("management acquire");
            return 0;
        }
        if (q.state == SLE_MANAGEMENT_FAULTED) return fail("management revocation fault");
        usleep(1000);
    } while (now() < deadline);
    return fail("management revocation deadline");
}

static int events_subscribe(int fd, unsigned long long generation)
{
    struct sle_controller_event_query request = { .version = 1, .generation = generation };
    struct pollfd p = { .fd = fd, .events = POLLIN };
    errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != EAGAIN ||
        poll(&p, 1, 0) != 0)
        return fail("empty native subscription uses its own cursor");
    return 0;
}

static int same(int fd, const struct sci_dev_info *expected, unsigned long long generation)
{
	struct sci_dev_info current;
	unsigned long long gen;
	if (ioctl(fd, SL_IOCTL_DEV_INFO, &current) || memcmp(current.addr, expected->addr, 6) ||
	    native_identity(expected->index, &gen) || gen != generation)
		return fail("unaffected native owner/generation");
	return 0;
}

static int stale(int fd)
{
	struct sci_dev_info info;
	errno = 0;
	return ioctl(fd, SL_IOCTL_DEV_INFO, &info) == -1 && errno == ENODEV ? 0 : fail("old fd must stay ENODEV");
}


static int query(int fd, const struct sci_dev_info *info, unsigned int opcode, unsigned int status)
{
    static uint64_t request_id;
    unsigned long long generation;
    if (native_identity(info->index, &generation) ||
        management_mode(fd, generation, SLE_MANAGEMENT_DIAGNOSTIC)) return -1;
    struct sle_diagnostic_submit cmd = { .version = 1, .generation = generation,
        .request_id = ++request_id, .timeout_ms = 5000, .opcode = opcode, .action = 1 };
    struct sle_mgmt_stats unsupported, unchanged;
    unsigned int length = opcode == 0x0403 ? 10 : opcode == 0x0404 ? 5 : 6;
    double deadline = now() + 5;
    memset(&unsupported, 0xa5, sizeof(unsupported)); unchanged = unsupported;
    if (ioctl(fd, SL_IOCTL_MGMT_STATS, &unsupported) != -1 || errno != EOPNOTSUPP ||
        memcmp(&unsupported, &unchanged, sizeof(unsupported)) ||
        ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &cmd) || !cmd.seq)
        return fail("typed query admission/Native stats refusal");
    struct sle_diagnostic_result result;
    for (;;) {
        result = (struct sle_diagnostic_result){ .version = 1, .generation = generation, .seq = cmd.seq };
        if (ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &result) || result.seq != cmd.seq ||
            result.generation != generation || result.opcode != opcode || result.error)
            return fail("typed query result identity/error");
        if (result.state != 1) break;
        if (now() >= deadline) return fail("typed query original deadline");
        usleep(1000);
    }
    if (result.state != (status ? 3U : 2U) || result.status != status ||
        result.data_len != (status ? 0 : length)) return fail("typed query terminal/status/length");
    if (!status && opcode == 0x0406 && memcmp(result.data, info->addr, 6))
        return fail("typed query MAC belongs to this owner");
    if (!status && opcode == 0x0403) {
        for (unsigned int i = 0; i < 10; i++)
            if (result.data[i] != info->addr[5]) return fail("all 80 feature bits belong to owner");
    }
    if (!status && opcode == 0x0404 && memcmp(result.data, "\x02\x01\x00\x01\x20", 5))
        return fail("complete version tuple");
    struct sle_diagnostic_submit replay = cmd; replay.seq = 0;
    if (ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &replay) || memcmp(&replay, &cmd, sizeof(cmd)))
        return fail("same author request must replay the original admission");
    struct sle_diagnostic_result repeated = { .version = 1, .generation = generation, .seq = cmd.seq };
    if (ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &repeated) || memcmp(&repeated, &result, sizeof(result)))
        return fail("typed result must remain author-bound and non-destructive");
    return 0;
}

static int exercise(int fd, const struct sci_dev_info *info)
{
    unsigned long long generation;
    if (native_identity(info->index, &generation) ||
        management_mode(fd, generation, SLE_MANAGEMENT_DIAGNOSTIC)) return -1;
    struct sle_diagnostic_submit invalid = { .version = 1, .generation = generation,
        .request_id = UINT64_MAX, .timeout_ms = 5000, .opcode = 0x0401, .action = 1 };
    struct sle_controller_snapshot before = { .version = 1, .generation = generation }, after = before;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &before)) return fail("typed invalid snapshot baseline");
    if (ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &invalid) != -1 || errno != EOPNOTSUPP)
        return fail("typed unsupported opcode");
    invalid.opcode = 0x0403;
    invalid.timeout_ms = 5001;
    if (ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &invalid) != -1 || errno != EINVAL ||
        ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &after) || memcmp(&before, &after, sizeof(before)))
        return fail("typed invalid deadline changed controller snapshot");
    for (unsigned int i = 0; i < 8; i++)
        if (query(fd, info, 0x0406, 0) || query(fd, info, 0x0403, 0)) return -1;
    if (query(fd, info, 0x0404, 0) || query(fd, info, 0x0402, 0)) return -1;
    printf("NATIVE_TYPED_HOST: index=%u queries=18 features=80 version=5 unsupported_opcode=1 invalid_timeout=1\n", info->index);
    return 0;
}
#endif
