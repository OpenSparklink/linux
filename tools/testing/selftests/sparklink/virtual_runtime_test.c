// SPDX-License-Identifier: GPL-2.0-only
/* Guest only: actual virtual driver + production Core/Host, never RF evidence. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
#include "../../../../drivers/sparklink/virtual.h"

struct controller { int control, fd; struct sparklink_virtual_status status; };
static unsigned int query_count;
static uint64_t request_id;
#define CHECK(expr) do { if (!(expr)) { \
	fprintf(stderr, "VIRTUAL_RUNTIME_FAIL line=%u errno=%d\n", __LINE__, errno); exit(1); } } while (0)

static double now(void)
{
	struct timespec ts;
	CHECK(!clock_gettime(CLOCK_MONOTONIC, &ts));
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static struct sle_controller_snapshot snapshot(struct controller c)
{
	struct sle_controller_snapshot s = { .version = 1, .generation = c.status.generation };
	CHECK(!ioctl(c.fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &s));
	CHECK(s.generation == c.status.generation && s.dev_index == c.status.id &&
	      s.bus == 6 && s.profile == 0 && !s.acb_count && !s.acb_length);
	return s;
}

static struct controller create(void)
{
	struct controller c = { .control = open("/dev/sparklink_virtual", O_RDWR),
		.fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK) };
	CHECK(c.control >= 0 && c.fd >= 0);
	CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &c.status));
	CHECK(c.status.live && c.status.generation && !c.status.pending);
	uint16_t id = c.status.id;
	CHECK(!ioctl(c.fd, SL_IOCTL_DEV_SELECT, &id));
	CHECK(snapshot(c).flags == SLE_CONTROLLER_SETUP);
	struct sle_management_request managed = { .version = 1,
		.generation = c.status.generation, .mode = SLE_MANAGEMENT_MANAGED };
	CHECK(ioctl(c.fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &managed) == -1 && errno == EOPNOTSUPP);
	struct sle_diagnostic_submit unauthorized = { .version = 1, .generation = c.status.generation,
		.request_id = 1, .timeout_ms = 5000, .opcode = 0x0404, .action = 1 };
	CHECK(ioctl(c.fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &unauthorized) == -1 && errno == EPERM);
	struct sle_dli_cmd legacy = { .opcode = 0x0404 };
	CHECK(ioctl(c.fd, SL_IOCTL_DLI_SEND_CMD, &legacy) == -1 && errno == EOPNOTSUPP);

	struct sle_management_request lease = { .version = 1,
		.generation = c.status.generation, .mode = SLE_MANAGEMENT_DIAGNOSTIC };
	CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &lease) && lease.lease);
	return c;
}

static void config(struct controller c, unsigned int delay, unsigned int drop, unsigned int fail)
{
	struct sparklink_virtual_control cfg = { .delay_ms = delay, .drop_next = drop,
		.fail_next = fail };
	CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_CONFIG, &cfg));
}

static uint32_t submit(struct controller c, uint16_t opcode)
{
	struct sle_diagnostic_submit cmd = { .version = 1, .generation = c.status.generation,
		.request_id = ++request_id, .timeout_ms = 5000, .opcode = opcode, .action = 1 };
	CHECK(!ioctl(c.fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &cmd) && cmd.seq);
	return cmd.seq;
}

static void query(struct controller c, uint16_t opcode, unsigned int length)
{
	struct sle_controller_snapshot s = snapshot(c);
	struct sle_mgmt_stats before, after;
	CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &before) && !before.pending);
	uint32_t seq = submit(c, opcode);
	double deadline = now() + 3;
	struct sle_diagnostic_result e;
	for (;;) {
		e = (struct sle_diagnostic_result){ .version = 1, .generation = c.status.generation, .seq = seq };
		CHECK(!ioctl(c.fd, SL_IOCTL_DIAGNOSTIC_RESULT, &e));
		CHECK(e.seq == seq && e.opcode == opcode && !e.error);
		if (e.state == 2) break;
		CHECK(e.state == 1 && now() < deadline);
		usleep(1000);
	}
	CHECK(!e.status && e.data_len == length);
	if (opcode == 0x0406) CHECK(!memcmp(e.data, s.address, 6));
	if (opcode == 0x0404) CHECK(!memcmp(e.data, s.version_tuple, 5));
	if (opcode == 0x0403) CHECK(!memcmp(e.data, s.features, 10));
	if (opcode == 0x0402) CHECK(!memcmp(e.data, (uint8_t[6]){}, 6));
	CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &after) && !after.pending &&
	      after.total_submitted == before.total_submitted + 1 &&
	      after.total_resolved == before.total_resolved + 1 &&
	      after.total_timeouts == before.total_timeouts);
	query_count++;
}

static void pending(struct controller c)
{
	double deadline = now() + 2;
	struct sparklink_virtual_status s;
	do {
		CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &s));
		if (s.pending) return;
		usleep(1000);
	} while (now() < deadline);
	CHECK(0);
}

static void stale(struct controller c)
{
	struct sle_controller_snapshot s = { .version = 1, .generation = c.status.generation };
	CHECK(ioctl(c.fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &s) == -1 && errno == ENODEV);
}

static void release_inflight_queries(struct controller c, struct controller peer)
{
	struct sle_management_query q = { .version = 1, .generation = c.status.generation };
	struct sle_mgmt_stats before, after;
	CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_QUERY, &q) && q.flags == 1 && q.lease);
	CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &before) && !before.pending);
	config(c, 500, 0, 0); submit(c, 0x0404); pending(c);
	submit(c, 0x0403); submit(c, 0x0406);
	struct sparklink_virtual_status driver_before, driver_after;
	CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &driver_before));
	struct sle_management_request release = { .version = 1, .generation = c.status.generation,
		.lease = q.lease, .mode = SLE_MANAGEMENT_DIAGNOSTIC };
	CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_RELEASE, &release));
	q = (struct sle_management_query){ .version = 1, .generation = c.status.generation };
	CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_QUERY, &q) && q.state == SLE_MANAGEMENT_REVOKING && !q.flags);
	query(peer, 0x0406, 6);
	double deadline = now() + 3;
	for (;;) {
		q = (struct sle_management_query){ .version = 1, .generation = c.status.generation };
		CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_QUERY, &q));
		if (q.state == SLE_MANAGEMENT_FREE) break;
		CHECK(q.state == SLE_MANAGEMENT_REVOKING && now() < deadline); usleep(1000);
	}
	CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &driver_after));
	CHECK(driver_after.submitted == driver_before.submitted && !driver_after.pending);
	CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &after) && !after.pending &&
		after.total_submitted == before.total_submitted + 3 && after.total_resolved == before.total_resolved + 3);
	CHECK(snapshot(c).flags == SLE_CONTROLLER_SETUP);
	struct sle_management_request acquire = { .version = 1, .generation = c.status.generation,
		.mode = SLE_MANAGEMENT_DIAGNOSTIC };
	CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &acquire));
	config(c, 0, 0, 0); query(c, 0x0406, 6);
	puts("VIRTUAL_QUERY_RELEASE_PASS: queued_cancel=2 inflight_reply=1 no_typed_stops=1 peer=1 setup=1");
}

static void fault(unsigned int delay, unsigned int drop, unsigned int fail,
		  struct controller peer)
{
	struct controller c = create();
	config(c, delay, drop, fail);
	submit(c, 0x0404);
	double deadline = now() + 8;
	struct sle_controller_snapshot s;
	do {
		s = snapshot(c);
		if (s.flags == SLE_CONTROLLER_FAULT) break;
		CHECK(now() < deadline);
		usleep(1000);
	} while (1);
	CHECK(s.error < 0 && !(s.flags & SLE_CONTROLLER_READY));
	if (delay) {
		struct sparklink_virtual_status status;
		do {
			CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &status));
			if (status.delivered) break;
			CHECK(now() < deadline);
			usleep(1000);
		} while (1);
		CHECK(snapshot(c).flags == SLE_CONTROLLER_FAULT);
	}
	query(peer, 0x0406, 6);
	CHECK(!close(c.control)); stale(c); CHECK(!close(c.fd));
	printf("VIRTUAL_FAULT: delay=%u drop=%u fail=%u peer_query=1 no_revive=1\n", delay, drop, fail);
}

int main(void)
{
	struct controller a = create(), b = create();
	CHECK(a.status.id != b.status.id && a.status.generation != b.status.generation);
	config(a, 20, 0, 0);
	const uint16_t queries[] = { 0x0401, 0x0402, 0x0403, 0x0404, 0x0406 };
	const unsigned int lengths[] = { 2, 6, 10, 5, 6 };
	for (unsigned int i = 0; i < 5; i++) {
		query(a, queries[i], lengths[i]); query(b, queries[i], lengths[i]);
	}
	release_inflight_queries(b, a);
	int alias = dup(a.control); CHECK(alias >= 0 && !close(a.control)); a.control = alias;
	query(a, 0x0406, 6);
	struct sparklink_virtual_control bad = { .delay_ms = 6001 };
	CHECK(ioctl(a.control, SPARKLINK_VIRTUAL_CONFIG, &bad) == -1 && errno == EINVAL);
	bad = (struct sparklink_virtual_control){ .drop_next = 33 };
	CHECK(ioctl(a.control, SPARKLINK_VIRTUAL_CONFIG, &bad) == -1 && errno == EINVAL);
	config(a, 6000, 0, 0); submit(a, 0x0404); pending(a);
	double began = now(); CHECK(!close(a.control)); CHECK(now() - began < 1); stale(a);
	struct controller replacement = create();
	CHECK(replacement.status.id == a.status.id && replacement.status.generation > a.status.generation);
	stale(a); query(replacement, 0x0406, 6); query(b, 0x0406, 6);
	CHECK(!close(a.fd));
	fault(0, 1, 0, b); fault(0, 0, 1, b); fault(6000, 0, 0, b);
	CHECK(!close(replacement.control)); CHECK(!close(replacement.fd));
	CHECK(!close(b.control)); CHECK(!close(b.fd));
	int fd = open("/dev/sparklink", O_RDWR); uint16_t mask = 0xffff;
	CHECK(fd >= 0 && !ioctl(fd, SL_IOCTL_DEV_LIST, &mask) && !mask); close(fd);
	printf("VIRTUAL_RUNTIME_PASS: query=%u dup=1 pending_last_close=1 reuse=1 stale=1 faults=3 empty=1 no_physical=1\n", query_count);
	return 0;
}
