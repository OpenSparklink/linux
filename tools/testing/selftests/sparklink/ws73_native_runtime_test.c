// SPDX-License-Identifier: GPL-2.0-only
/* Synthetic WS73 USB/Runtime gate. No RF, slkd or ordinary-user acceptance. */
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"

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
		if (read != 1 || strcmp(stage, "native-runtime-setup") || !streaming || broken || !gen)
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

static int query(int fd, const struct sci_dev_info *info, unsigned int opcode, unsigned int status)
{
	struct sle_dli_cmd cmd = { .opcode = opcode };
	struct sle_mgmt_stats before, after;
	unsigned int length = opcode == 0x0403 ? 10 : opcode == 0x0404 ? 5 : 6;
	double deadline = now() + 10;
	int received = 0;

	if (opcode == 0x0406)
		cmd.param_len = 1; /* explicit public address type 0 */
	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &before) || before.pending ||
	    ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &cmd))
		return fail("query submit/quiet baseline");
	while (now() < deadline) {
		struct sle_dli_event event = { 0 };
		if (!ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &event)) {
			if (event.opcode != opcode || (event.event_type != 1 && !event.status))
				continue;
			if (event.status != status || event.data_len != (status ? 0 : length))
				return fail("exact native status/value length");
			if (!status && opcode == 0x0406 && memcmp(event.data, info->addr, 6))
				return fail("MAC belongs to this owner");
			if (!status && opcode == 0x0403) {
				for (unsigned int i = 0; i < 10; i++)
					if (event.data[i] != info->addr[5])
						return fail("all 80 feature bits belong to this owner");
			}
			if (!status && opcode == 0x0404 && memcmp(event.data, "\x02\x01\x00\x01\x20", 5))
				return fail("complete five-byte version tuple");
			received = 1;
			break;
		} else if (errno != EAGAIN) {
			return fail("query poll");
		}
		usleep(1000);
	}
	if (!received || ioctl(fd, SL_IOCTL_MGMT_STATS, &after) || after.pending ||
	    after.total_submitted != before.total_submitted + 1 ||
	    after.total_resolved != before.total_resolved + 1 || after.total_timeouts != before.total_timeouts)
		return fail("native transaction/count/deadline");
	return 0;
}

static int exercise(int fd, const struct sci_dev_info *info)
{
	struct sle_dli_cmd wrong = { .opcode = 0x0401 };
	struct sle_mgmt_stats before, after;

	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &before))
		return fail("before unsupported dialect operation");
	errno = 0;
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &wrong) != -1 || errno != EOPNOTSUPP ||
	    ioctl(fd, SL_IOCTL_MGMT_STATS, &after) || memcmp(&before, &after, sizeof(before)))
		return fail("ReadCmdLen rejected before credit/pending consumption");
	/* A declared parameter length must never be clamped to the ABI buffer.
	 * Same unsupported opcode distinguishes EINVAL from dialect rejection.
	 */
	wrong.param_len = 0xffff;
	errno = 0;
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &wrong) != -1 || errno != EINVAL ||
	    ioctl(fd, SL_IOCTL_MGMT_STATS, &after) || memcmp(&before, &after, sizeof(before)))
		return fail("oversized parameters rejected before dialect/pending/credit");
	wrong = (struct sle_dli_cmd){ .opcode = 0x1002, .param_len = 2, .params = { 1, 0 } };
	errno = 0;
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &wrong) != -1 || errno != EOPNOTSUPP ||
	    ioctl(fd, SL_IOCTL_MGMT_STATS, &after) || memcmp(&before, &after, sizeof(before)))
		return fail("discovery schema is not Runtime support until event route exists");
	wrong = (struct sle_dli_cmd){ .opcode = 0x0406, .param_len = 1, .params = { 2 } };
	errno = 0;
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &wrong) != -1 || errno != EINVAL ||
	    ioctl(fd, SL_IOCTL_MGMT_STATS, &after) || memcmp(&before, &after, sizeof(before)))
		return fail("driver query parameter rejected before pending/credit");
	for (int i = 0; i < 8; i++)
		if (query(fd, info, 0x0406, 0) || query(fd, info, 0x0403, 0))
			return -1;
	if (query(fd, info, 0x0404, 0) || query(fd, info, 0x0402, 0))
		return -1;
	printf("NATIVE_HOST: index=%u queries=18 features=80 version=5 dialect_reject=1\n", info->index);
	return 0;
}

/* Complete native event gate. All packets are injected by the NO-RF fixture. */
_Static_assert(sizeof(struct sle_controller_event) == 336, "event ABI");
_Static_assert(sizeof(struct sle_controller_event_query) == 360, "event query ABI");
_Static_assert(SL_IOCTL_CONTROLLER_EVENT_GET == 0xc1685387U, "event ioctl ABI");

static int events_subscribe(int fd, unsigned long long generation)
{
    struct sle_controller_event_query request = { .version = 1, .generation = generation };
    struct pollfd p = { .fd = fd, .events = POLLIN };
    errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != EAGAIN ||
        poll(&p, 1, 0) != 0)
        return fail("empty native subscription ignores queued legacy replies");
    return 0;
}

static int events_read(int fd, const struct sci_dev_info *info, unsigned long long generation,
                       struct sle_controller_event *first)
{
    struct sle_controller_event_query request = { .version = 1, .generation = generation };
    struct pollfd p = { .fd = fd, .events = POLLIN };
    unsigned long long timestamp = 0;
    if (poll(&p, 1, 1000) != 1 || p.revents != POLLIN)
        return fail("native subscription readiness");
    for (unsigned int ordinal = 9; ordinal <= 40; ordinal++) {
        if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request))
            return fail("complete native record read");
        const struct sle_controller_event *e = &request.event;
        const unsigned char *b = e->payload;
        if (e->seq != ordinal || e->generation != generation || e->dev_index != info->index ||
            e->profile != 1 || e->event_code != 0x180b || e->payload_len != 278 ||
            e->flags || e->_reserved || e->lost != (ordinal == 9 ? 8U : 0U) ||
            !e->timestamp_ns || e->timestamp_ns < timestamp || b[0] != 3 || b[1] != 6 ||
            memcmp(b + 2, "\xaa\xbb\xcc\xdd\xee", 5) || b[7] != info->addr[5] ||
            b[8] != 4 || memcmp(b + 9, "\x09\x08\x07\x06\x05\x04", 6) ||
            memcmp(b + 15, "\x01\x02\x03\x44\x55\xa7\xd6\xff", 8))
            return fail("native identity/header/loss/timestamp preserved");
        for (unsigned int i = 0; i < 255; i++)
            if (b[23 + i] != (unsigned char)(i ^ ordinal))
                return fail("maximum report data is not truncated");
        for (unsigned int i = 278; i < sizeof(e->payload); i++)
            if (b[i])
                return fail("unused event bytes are zero");
        if (ordinal == 9)
            *first = *e;
        timestamp = e->timestamp_ns;
        request.after_seq = e->seq;
    }
    errno = 0;
    p.revents = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != EAGAIN ||
        poll(&p, 1, 0) != 0)
        return fail("native cursor caught up");
    return 0;
}

static int events_gate(int fd, int reader, const struct sci_dev_info *info,
                       unsigned long long generation)
{
    struct sle_controller_event_query request = { .version = 2, .generation = generation };
    struct sle_controller_event first, second;
    const unsigned int fields[][2] = { {2, 0}, {1, 1} };
    for (unsigned int i = 0; i < 2; i++) {
        request.version = fields[i][0]; request.flags = fields[i][1]; errno = 0;
        if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 ||
            errno != (i ? EINVAL : EOPNOTSUPP))
            return fail("event version/flags validation");
    }
    request.version = 1; request.flags = 0; request.after_seq = 41; errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != EINVAL)
        return fail("future event cursor rejected");
    request.after_seq = 1; request.generation = 0; errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != EINVAL)
        return fail("noninitial cursor requires generation");
    request.after_seq = 0; request.generation = generation + 100; errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != ENODEV)
        return fail("cross-registration event generation rejected");
    request.generation = generation;
    void *readonly = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (readonly == MAP_FAILED)
        return fail("event copy-fault mapping");
    memcpy(readonly, &request, sizeof(request));
    if (mprotect(readonly, 4096, PROT_READ)) {
        munmap(readonly, 4096); return fail("event copy-fault protection");
    }
    errno = 0;
    int result = ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, readonly), error = errno;
    munmap(readonly, 4096);
    if (result != -1 || error != EFAULT || events_read(fd, info, generation, &first) ||
        events_read(reader, info, generation, &second) || memcmp(&first, &second, sizeof(first)))
        return fail("copy fault retry and independent complete fanout");
    printf("NATIVE_EVENTS: index=%u retained=32 first=9 last=40 lost=8 payload=278 fanout=2 fault_retry=1 poll=1\n", info->index);
    return 0;
}

static int events_retired(int fd, unsigned long long generation)
{
    struct sle_controller_event_query request = { .version = 1, .generation = generation, .after_seq = 40 };
    struct pollfd p = { .fd = fd, .events = POLLIN };
    errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_EVENT_GET, &request) != -1 || errno != ENODEV ||
        poll(&p, 1, 1000) != 1 || !(p.revents & POLLHUP))
        return fail("retired event subscription ENODEV/HUP");
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

static int wait_interfaces(int expected)
{
    double deadline = now() + 10;
    while (now() < deadline) {
        DIR *dir = opendir("/sys/bus/usb/drivers/sparklink_ws73_usb");
        struct dirent *entry;
        int count = 0;
        if (dir) {
            while ((entry = readdir(dir)))
                if (strchr(entry->d_name, ':'))
                    count++;
            closedir(dir);
        }
        if (count == expected)
            return 0;
        usleep(10000);
    }
    return fail("USB interface removal deadline");
}

static int wait_failed_driver(void)
{
    double deadline = now() + 3;
    while (now() < deadline) {
        DIR *dir = opendir("/sys/bus/usb/drivers/sparklink_ws73_usb");
        struct dirent *entry;
        int found = 0;
        if (!dir)
            return fail("fault sysfs");
        while ((entry = readdir(dir))) {
            char path[512], stage[64];
            FILE *file;
            int error = 0;
            if (!strchr(entry->d_name, ':'))
                continue;
            snprintf(path, sizeof(path), "/sys/bus/usb/drivers/sparklink_ws73_usb/%s/boot_error", entry->d_name);
            file = fopen(path, "r");
            if (!file)
                continue;
            int parsed = fscanf(file, "%d", &error);
            fclose(file);
            if (parsed != 1 || error != -EPROTO)
                continue;
            snprintf(path, sizeof(path), "/sys/bus/usb/drivers/sparklink_ws73_usb/%s/boot_stage", entry->d_name);
            file = fopen(path, "r");
            if (!file)
                continue;
            parsed = fscanf(file, "%63s", stage);
            fclose(file);
            if (parsed == 1 && !strcmp(stage, "failed"))
                found++;
        }
        closedir(dir);
        if (found == 1)
            return 0;
        usleep(10000);
    }
    return fail("single native driver fault stage/errno");
}

static uint64_t discovery_id = 100;
static int discovery_read(int fd, unsigned long long gen, uint64_t id,
			  struct sle_discovery_result *result)
{
	*result = (struct sle_discovery_result){ .version = 1,
						 .generation = gen,
						 .request_id = id };
	if (ioctl(fd, SL_IOCTL_DISCOVERY_RESULT, result))
		return fail("operation result query");
	return 0;
}
static void discovery_request(struct sle_discovery_submit *r,
			      unsigned long long gen, unsigned int op,
			      const struct sci_dev_info *info)
{
	*r = (struct sle_discovery_submit){ .version = 1,
					    .profile = 1,
					    .generation = gen,
					    .request_id = discovery_id++,
					    .operation = op };
	if (op <= 2)
		r->handle = 7;
	if (op == 1) {
		r->advertising.handle = 7;
		r->advertising.interval_min = 800;
		r->advertising.interval_max = 800;
		r->advertising.channel_map = 7;
		r->advertising.primary_frame = 1;
		r->advertising.tx_power = 0;
		memcpy(r->advertising.own_address, info->addr, 6);
		r->flags = 1;
		r->data_len = 6;
		r->scan_response_len = 6;
		memcpy(r->data, "\x05\x09WS73", 6);
		memcpy(r->scan_response, "\x05\x09RSP!", 6);
	}
	if (op == 3) {
		r->scanning.frame_types = 1;
		r->scanning.interval = 800;
		r->scanning.window = 400;
	}
}
static int discovery_wait(int fd, unsigned long long gen,
			  struct sle_discovery_submit *r, unsigned int expected,
			  struct sle_discovery_result *result)
{
	double deadline = now() + 8;
	while (now() < deadline) {
		if (discovery_read(fd, gen, r->request_id, result))
			return -1;
		if (result->operation != r->operation ||
		    result->generation != gen ||
		    result->request_id != r->request_id)
			return fail("operation attribution");
		if (result->state >= 3) {
			if (result->state != expected)
				return fail("operation terminal state");
			struct sle_discovery_result again;
			if (discovery_read(fd, gen, r->request_id, &again) ||
			    memcmp(result, &again, sizeof(again)))
				return fail("non-destructive stable result");
			return 0;
		}
		usleep(2000);
	}
	return fail("operation result deadline");
}
static int discovery_do(int fd, unsigned long long gen, unsigned int op,
			const struct sci_dev_info *info,
			struct sle_discovery_result *result)
{
	struct sle_discovery_submit r;
	discovery_request(&r, gen, op, info);
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) ||
	    discovery_wait(fd, gen, &r, 3, result))
		return fail("typed operation submit/complete");
	if (result->status || result->error ||
	    result->step + 1 != result->count)
		return fail("successful complete fields");
	if (op == 1 && (!result->power_valid || result->selected_power != -42 ||
			result->count != 4))
		return fail("actual selected power/full recipe");
	return 0;
}
static int controller_snapshot(int fd, unsigned long long gen,
                               const struct sci_dev_info *info,
                               unsigned int expected, int expected_error)
{
    struct sle_controller_snapshot out = { .version = 1, .generation = gen };
    const unsigned char version[5] = { 2, 1, 0, 1, 0x20 };
    if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &out) || out.generation != gen ||
        out.version != 1 || out.profile != 1 || out.dev_index != info->index ||
        out.flags != expected || out.error != expected_error || out.valid_fields != 1 ||
        memcmp(out.version_tuple, version, 5) || memcmp(out.address, info->addr, 6) ||
        out.acb_length != 254 || out.icb_length || out.acb_count != 5 || out.icb_count ||
        out.reserved_byte || memcmp(out.reserved, "\0\0\0\0", 4))
        return fail("complete controller snapshot metadata/state/error");
    /* Synthetic query fixture returns this owner's serial in all ten bytes. */
    for (unsigned int i = 0; i < 10; i++)
        if (out.features[i] != info->addr[5])
            return fail("all ten feature bytes queried for selected owner");
    return 0;
}

static int discovery_gate(int fd, unsigned long long gen,
			  const struct sci_dev_info *info)
{
	struct sle_discovery_result result;
	struct sle_discovery_submit r, stop;
	if (discovery_read(fd, 0, 0, &result) || result.generation != gen ||
	    result.profile != 1 || result.dev_index != info->index ||
	    result.radio_adv || result.radio_scan || result.flags)
		return fail("initial identity/unknown radio probe");
	if (controller_snapshot(fd, gen, info, SLE_CONTROLLER_SETUP, 0) ||
	    discovery_do(fd, gen, 2, info, &result) ||
	    controller_snapshot(fd, gen, info, SLE_CONTROLLER_SETUP, 0) ||
	    discovery_do(fd, gen, 4, info, &result) ||
	    controller_snapshot(fd, gen, info, SLE_CONTROLLER_READY, 0))
		return -1;
	for (int round = 0; round < 5; round++) {
		if (discovery_do(fd, gen, 1, info, &result) ||
		    result.radio_adv != 2 ||
		    discovery_do(fd, gen, 2, info, &result) ||
		    result.radio_adv != 1 ||
		    discovery_do(fd, gen, 3, info, &result) ||
		    result.radio_scan != 2 ||
		    discovery_do(fd, gen, 4, info, &result) ||
		    result.radio_scan != 1)
			return fail("radio confirmation/role swap");
	}
	discovery_request(&r, gen, 1, info);
	r.flags = 0; r.scan_response_len = 0; memset(r.scan_response, 0, sizeof(r.scan_response));
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) || discovery_wait(fd, gen, &r, 3, &result) ||
	    result.count != 3 || !result.power_valid || result.selected_power != -42 ||
	    discovery_do(fd, gen, 2, info, &result))
		return fail("optional response omitted -> exact three-step operation");
	for (unsigned int step = 0; step < 4; step++) {
		discovery_request(&r, gen, 1, info);
		r.advertising.mode =
			0xf0 + step; /* explicit synthetic fixture trigger */
		if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) ||
		    discovery_wait(fd, gen, &r, 4, &result) ||
		    result.status != 0xfd || result.error ||
		    result.step != step || result.count != 4 ||
		    result.radio_adv != 1)
			return fail("failure step/raw status/no enable");
	}
	discovery_request(&r, gen, 1, info);
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r))
		return fail("cancelled start submit");
	discovery_request(&stop, gen, 2, info);
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &stop) ||
	    discovery_wait(fd, gen, &r, 5, &result) ||
	    result.error != -ECANCELED ||
	    discovery_wait(fd, gen, &stop, 3, &result) || result.radio_adv != 1)
		return fail("start cancellation/stop barrier");
	discovery_request(&r, gen, 1, info);
	r.advertising.mode = 0xee;
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) ||
	    discovery_wait(fd, gen, &r, 3, &result))
		return -1;
	discovery_request(&stop, gen, 2, info);
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &stop))
		return fail("failed stop submit");
	if (discovery_wait(fd, gen, &stop, 4, &result) ||
	    result.status != 0xfd || result.radio_adv != 2 ||
	    discovery_do(fd, gen, 2, info, &result) || result.radio_adv != 1)
		return fail("stop failure stays on/retry");
	/* Invalid submission/duplicate/stale generation never allocate an operation. */
	errno = 0;
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &stop) != -1 ||
	    errno != EEXIST)
		return fail("duplicate request id");
	discovery_request(&r, gen, 1, info);
	r.reserved = 1;
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) != -1 || errno != EINVAL)
		return fail("reserved submit rejected");
	result = (struct sle_discovery_result){ .version = 1,
						.generation = gen,
						.request_id = r.request_id };
	if (ioctl(fd, SL_IOCTL_DISCOVERY_RESULT, &result) != -1 ||
	    errno != ENOENT)
		return fail("invalid submit no result");
	r.reserved = 0;
	r.generation = gen + 1000;
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) != -1 || errno != ENODEV)
		return fail("wrong operation generation");
	/* A result copyout fault does not consume the entry. */
	long page = sysconf(_SC_PAGESIZE);
	void *readonly = mmap(NULL, page, PROT_READ | PROT_WRITE,
			      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (readonly == MAP_FAILED)
		return fail("result fault page");
	*(struct sle_discovery_result *)readonly =
		(struct sle_discovery_result){ .version = 1,
					       .generation = gen,
					       .request_id = stop.request_id };
	if (mprotect(readonly, page, PROT_READ))
		return fail("result fault protection");
	errno = 0;
	int ret = ioctl(fd, SL_IOCTL_DISCOVERY_RESULT, readonly);
	munmap(readonly, page);
	if (ret != -1 || errno != EFAULT ||
	    discovery_read(fd, gen, stop.request_id, &result) ||
	    result.state != 4)
		return fail("result EFAULT retry preserves failed stop");
	struct sle_dli_cmd raw = { .opcode = 0x0c05, .param_len = 5 };
	raw.params[1] = 7;
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &raw) != -1 ||
	    errno != EOPNOTSUPP || query(fd, info, 0x0406, 0))
		return fail("typed support never broadens raw whitelist");
	struct sle_controller_snapshot invalid = { .version = 1, .reserved_byte = 1 };
	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &invalid) != -1 || errno != EINVAL)
		return fail("snapshot reserved byte rejected");
	invalid = (struct sle_controller_snapshot){ .version = 1, .generation = gen + 1000 };
	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &invalid) != -1 || errno != ENODEV)
		return fail("snapshot generation rejected");
	printf("NATIVE_CONTROLLER_STATE: index=%u setup_then_ready=1 version=5 features=80\n", info->index);
	printf("NATIVE_DISCOVERY: index=%u cycles=5 failures=4 stop_failure=1 cancel=1 power=-42 snapshots=1 raw_reject=1 no_rsp=1\n",
	       info->index);
	return 0;
}
static int discovery_timeout(int fd, unsigned long long gen,
			     const struct sci_dev_info *info)
{
	struct sle_discovery_submit r;
	struct sle_discovery_result result;
	discovery_id = 10000; /* parent has not consumed child-generated ids */
	discovery_request(&r, gen, 1, info);
	r.advertising.mode = 0xed;
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) ||
	    discovery_wait(fd, gen, &r, 6, &result) ||
	    result.error != -ETIMEDOUT || result.flags != 1 ||
	    result.radio_adv || result.radio_scan)
		return fail("missing Complete -> isolated uncertain fault");
	discovery_request(&r, gen, 2, info);
	if (ioctl(fd, SL_IOCTL_DISCOVERY_SUBMIT, &r) != -1 ||
	    errno != ETIMEDOUT)
		return fail("fault cannot invent credits/recover silently");
	if (controller_snapshot(fd, gen, info, SLE_CONTROLLER_FAULT, -ETIMEDOUT))
		return -1;
	puts("NATIVE_CONTROLLER_FAULT: index=0 ready_cleared=1 errno=110");
	puts("NATIVE_DISCOVERY_TIMEOUT: index=0 errno=110 radio_unknown=1");
	return 0;
}

int main(int argc, char **argv)
{
	struct sci_dev_info a_info, b_info, replacement_info;
	unsigned long long a_gen, b_gen, replacement_gen;
	int control = open("/dev/sparklink", O_RDWR | O_NONBLOCK), a = -1,
	    b = -1, replacement = -1;
	int complete = 0, readers[2] = { -1, -1 };
	pid_t children[2];
	int fault_mode = argc == 2 && !strcmp(argv[1], "--fault");
	int event_mode = argc == 2 && !strcmp(argv[1], "--events");
	int discovery_mode = argc == 2 && !strcmp(argv[1], "--discovery");
	if (argc != 1 && !fault_mode && !event_mode && !discovery_mode)
		return 2;

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (control < 0 || mask_wait(control, 1))
		goto out;
	a = bind_owner(0, &a_info, &a_gen);
	if (a < 0 || (!fault_mode && query(a, &a_info, 0x0406, 0xfe)))
		goto out;
	if (!fault_mode)
		puts("NATIVE_RAW_STATUS: fe preserved");
	if (discovery_mode) {
		struct sle_controller_snapshot unselected = { .version = 1 };
		if (ioctl(control, SL_IOCTL_CONTROLLER_SNAPSHOT, &unselected) != -1 || errno != EINVAL)
			goto out;
		struct sle_discovery_result unbound = { .version = 1 };
		if (ioctl(control, SL_IOCTL_DISCOVERY_RESULT, &unbound) != -1 ||
		    errno != EINVAL)
			goto out;
	}
	puts("NATIVE_ADD_SECOND");
	if (mask_wait(control, 3))
		goto out;
	b = bind_owner(1, &b_info, &b_gen);
	if (b < 0 || same(a, &a_info, a_gen))
		goto out;
	if (event_mode) {
		struct sci_dev_info unused;
		unsigned long long reader_gen;
		readers[0] = bind_owner(0, &unused, &reader_gen);
		if (readers[0] < 0 || reader_gen != a_gen)
			goto out;
		readers[1] = bind_owner(1, &unused, &reader_gen);
		if (readers[1] < 0 || reader_gen != b_gen ||
		    events_subscribe(a, a_gen) || events_subscribe(b, b_gen) ||
		    events_subscribe(readers[0], a_gen) ||
		    events_subscribe(readers[1], b_gen))
			goto out;
	}
	if (fault_mode) {
		struct sle_dli_cmd cmd = { .opcode = 0x0406, .param_len = 1 };
		if (exercise(b, &b_info) ||
		    ioctl(a, SL_IOCTL_DLI_SEND_CMD, &cmd) ||
		    mask_wait(control, 2) || stale(a) ||
		    same(b, &b_info, b_gen) || query(b, &b_info, 0x0406, 0))
			goto out;
		if (wait_failed_driver())
			goto out;
		puts("NATIVE_FAULT: id=0 removed errno=71");
		puts("NATIVE_FAULT_FIRST");
		if (wait_interfaces(1))
			goto out;
	} else {
		for (int i = 0; i < 2; i++) {
			children[i] = fork();
			if (!children[i])
				exit((exercise(i ? b : a,
					       i ? &b_info : &a_info) ||
				      (discovery_mode &&
				       discovery_gate(i ? b : a,
						      i ? b_gen : a_gen,
						      i ? &b_info : &a_info))) ?
					     1 :
					     0);
		}
		for (int i = 0; i < 2; i++) {
			int status;
			if (children[i] < 0 ||
			    waitpid(children[i], &status, 0) != children[i] ||
			    !WIFEXITED(status) || WEXITSTATUS(status))
				failed = 1;
		}
		if (failed)
			goto out;
		if (event_mode && (events_gate(a, readers[0], &a_info, a_gen) ||
				   events_gate(b, readers[1], &b_info, b_gen)))
			goto out;
		if (discovery_mode && (discovery_timeout(a, a_gen, &a_info) ||
				       query(b, &b_info, 0x0406, 0)))
			goto out;
		puts("NATIVE_REMOVE_FIRST");
		if (mask_wait(control, 2) || stale(a) ||
		    same(b, &b_info, b_gen) || query(b, &b_info, 0x0406, 0))
			goto out;
	}
	if (event_mode &&
	    (events_retired(a, a_gen) || events_retired(readers[0], a_gen)))
		goto out;
	puts("NATIVE_READD_FIRST");
	if (mask_wait(control, 3) || stale(a) || same(b, &b_info, b_gen))
		goto out;
	replacement = bind_owner(0, &replacement_info, &replacement_gen);
	if (replacement < 0 || replacement_gen == a_gen ||
	    !memcmp(a_info.addr, replacement_info.addr, 6) ||
	    query(replacement, &replacement_info, 0x0406, 0) ||
	    query(b, &b_info, 0x0406, 0) || stale(a))
		goto out;
	if (event_mode) {
		struct sle_controller_event first;
		if (query(replacement, &replacement_info, 0x0404, 0) ||
		    events_read(replacement, &replacement_info, replacement_gen,
				&first) ||
		    events_retired(a, a_gen))
			goto out;
		puts("NATIVE_EVENTS_REPLUG: seq=9 lost=8 old_hup=1 new_generation=1");
	}
	if (discovery_mode) {
		struct sle_discovery_result fresh;
		if (discovery_read(replacement, 0, 0, &fresh) ||
		    fresh.generation != replacement_gen || fresh.flags ||
		    fresh.radio_adv || fresh.radio_scan)
			goto out;
		fresh = (struct sle_discovery_result){ .version = 1,
						       .generation = a_gen,
						       .request_id = 100 };
		if (ioctl(replacement, SL_IOCTL_DISCOVERY_RESULT, &fresh) !=
			    -1 ||
		    errno != ENODEV)
			goto out;
		fresh = (struct sle_discovery_result){ .version = 1,
						       .generation =
							       replacement_gen,
						       .request_id = 100 };
		if (ioctl(a, SL_IOCTL_DISCOVERY_RESULT, &fresh) != -1 ||
		    errno != ENODEV ||
		    ioctl(replacement, SL_IOCTL_DISCOVERY_RESULT, &fresh) !=
			    -1 ||
		    errno != ENOENT)
			goto out;
		puts("NATIVE_DISCOVERY_REPLUG: fault_reset=1 old_generation=1");
	}
	printf("NATIVE_LIFETIME: old=%llu new=%llu unaffected=%llu\n", a_gen,
	       replacement_gen, b_gen);
	complete = 1;
	puts("NATIVE_LIFECYCLE: PASS");
out:
	if (!complete && !failed)
		fail("gate ended before completion");
	if (control < 0)
		fail("control open");
	if (replacement >= 0)
		close(replacement);
	if (b >= 0)
		close(b);
	if (a >= 0)
		close(a);
	for (int i = 0; i < 2; i++)
		if (readers[i] >= 0)
			close(readers[i]);
	if (control >= 0)
		close(control);
	return failed ? 1 : 0;
}
