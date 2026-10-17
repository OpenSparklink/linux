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
#include <sys/wait.h>
#include <grp.h>
#define GENL_REGISTRY_EMBEDDED
#include "genl_registry_test.c"
#define PROTOCOL_STATE_EMBEDDED
#include "protocol_state_unsupported_test.c"
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
	unsigned char legacy_read[64]; memset(legacy_read, 0xa5, sizeof(legacy_read));
	CHECK(read(c.fd, legacy_read, sizeof(legacy_read)) == -1 && errno == EOPNOTSUPP);
	CHECK(ioctl(c.fd, 0x5370U, NULL) == -1 && errno == ENOTTY);
	CHECK(ioctl(c.fd, 0x80205371U, legacy_read) == -1 && errno == ENOTTY);
	for (unsigned n = 0; n < sizeof(legacy_read); n++) CHECK(legacy_read[n] == 0xa5);

	/* Unpublished legacy poll was deleted; it cannot consume any reply. */
	unsigned char retired[256];
	memset(retired, 0xa5, sizeof(retired));
	CHECK(ioctl(c.fd, 0x81005382U, retired) == -1 && errno == ENOTTY);
	for (unsigned int i = 0; i < sizeof(retired); i++) CHECK(retired[i] == 0xa5);
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

static void standard_snoop(struct controller c, struct controller peer)
{
    int fds[2] = {open("/dev/sparklink",O_RDWR),open("/dev/sparklink",O_RDWR)};
    struct sle_snoop_query q[2] = {{.version=1,.generation=c.status.generation},{.version=1,.generation=c.status.generation}};
    int16_t id=c.status.id;
    for(unsigned i=0;i<2;i++) {
        CHECK(fds[i]>=0 && !ioctl(fds[i],SL_IOCTL_DEV_SELECT,&id));
        struct sle_snoop_query invalid=q[i], before;
        invalid.flags=1;before=invalid;errno=0;
        CHECK(ioctl(fds[i],SL_IOCTL_SNOOP_GET,&invalid)==-1 && errno==EINVAL && !memcmp(&invalid,&before,sizeof(invalid)));
        invalid=q[i];invalid.reserved=1;before=invalid;errno=0;
        CHECK(ioctl(fds[i],SL_IOCTL_SNOOP_GET,&invalid)==-1 && errno==EINVAL && !memcmp(&invalid,&before,sizeof(invalid)));
        errno=0;CHECK(ioctl(fds[i],SL_IOCTL_SNOOP_GET,&q[i])==-1 && errno==EAGAIN);
    }
    config(c,20,0,0);query(c,0x0402,6);
    unsigned directions[2]={0,0};
    for(unsigned n=0;n<2;n++) {
        for(unsigned i=0;i<2;i++) {
            CHECK(!ioctl(fds[i],SL_IOCTL_SNOOP_GET,&q[i]));
            struct sle_snoop_record *s=&q[i].record;
            CHECK(s->profile==0 && s->format==2 && s->generation==c.status.generation && s->dev_index==c.status.id && !s->lost && !s->status && !s->flags);
            CHECK(s->direction==1 || s->direction==2);
            CHECK(!(directions[i] & (1U<<s->direction))); directions[i]|=1U<<s->direction;
            if(s->direction==2)CHECK(s->captured_length==4 && !memcmp(s->payload,(uint8_t[4]){2,4,0,0},4));
            else CHECK(s->captured_length==14 && !memcmp(s->payload,(uint8_t[14]){2,0,10,0,2,4,1,0},14));
        }
        CHECK(!memcmp(&q[0].record,&q[1].record,sizeof(q[0].record)));
        for(unsigned i=0;i<2;i++)q[i].after_seq=q[i].record.seq;
    }
    CHECK(directions[0]==6 && directions[1]==6);
    fflush(NULL);pid_t child=fork();CHECK(child>=0);
    if(!child) {
        CHECK(!setgroups(0,NULL) && !setgid(1000) && !setuid(1000));
        struct sle_snoop_query before=q[0];errno=0;
        CHECK(ioctl(fds[0],SL_IOCTL_SNOOP_GET,&q[0])==-1 && errno==EPERM && !memcmp(&before,&q[0],sizeof(before)));
        struct pollfd p={.fd=fds[0],.events=POLLIN};CHECK(poll(&p,1,0)==1 && (p.revents&POLLERR));
        _exit(0);
    }
    int status;CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && !WEXITSTATUS(status));
    query(peer,0x0406,6);
    CHECK(!close(fds[0]) && !close(fds[1]));
    printf("VIRTUAL_STANDARD_SNOOP_PASS: readers=2 exact_tx_rx=1 independent=1 flags_reserved=EINVAL inherited_CAP=EPERM peer_query=1 no_rf=1\n");
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

static struct controller diagnostic_fd_lifetime(struct controller c, struct controller peer)
{
	int alias = dup(c.fd);
	CHECK(alias >= 0 && !close(c.fd));
	c.fd = alias;
	query(c, 0x0406, 6);
	struct controller observer = c;
	observer.fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	uint16_t id = c.status.id;
	CHECK(observer.fd >= 0 && !ioctl(observer.fd, SL_IOCTL_DEV_SELECT, &id));
	struct sle_mgmt_stats before, after;
	CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &before) && !before.pending);
	config(c, 800, 0, 0);
	submit(c, 0x0404); pending(c);
	submit(c, 0x0403); submit(c, 0x0406);
	alias = dup(c.fd);
	CHECK(alias >= 0 && !close(c.fd));
	c.fd = alias;
	struct sle_management_query q = { .version = 1, .generation = c.status.generation };
	CHECK(!ioctl(c.fd, SL_IOCTL_MANAGEMENT_QUERY, &q) && q.state == SLE_MANAGEMENT_HELD && q.flags == 1);
	struct sparklink_virtual_status driver_before, driver_after;
	CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &driver_before) && driver_before.pending);
	CHECK(!close(c.fd));
	q = (struct sle_management_query){ .version = 1, .generation = c.status.generation };
	CHECK(!ioctl(observer.fd, SL_IOCTL_MANAGEMENT_QUERY, &q) && q.state == SLE_MANAGEMENT_REVOKING && !q.flags);
	query(peer, 0x0406, 6);
	double deadline = now() + 3;
	for (;;) {
		q = (struct sle_management_query){ .version = 1, .generation = c.status.generation };
		CHECK(!ioctl(observer.fd, SL_IOCTL_MANAGEMENT_QUERY, &q));
		if (q.state == SLE_MANAGEMENT_FREE) break;
		CHECK(q.state == SLE_MANAGEMENT_REVOKING && now() < deadline);
		usleep(1000);
	}
	CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &driver_after) && !driver_after.pending &&
	      driver_after.submitted == driver_before.submitted);
	CHECK(!ioctl(observer.fd, SL_IOCTL_MGMT_STATS, &after) && !after.pending &&
	      after.total_submitted == before.total_submitted + 3 && after.total_resolved == before.total_resolved + 3);
	CHECK(snapshot(observer).flags == SLE_CONTROLLER_SETUP);
	struct sle_management_request acquire = { .version = 1, .generation = c.status.generation,
		.mode = SLE_MANAGEMENT_DIAGNOSTIC };
	CHECK(!ioctl(observer.fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &acquire));
	config(observer, 0, 0, 0);
	query(observer, 0x0406, 6);
	puts("VIRTUAL_DIAGNOSTIC_FD_PASS: dup_keeps_lease=1 final_close_revokes=1 queued_cancel=2 inflight_reply=1 peer=1");
	return observer;
}

/* Explicit test-only error travels through the real parser/Host/worker. */
static void hardware_error_fault(struct controller peer)
{
    struct controller c = create();
    _Static_assert(sizeof(struct sparklink_virtual_status) == 64, "private status callback barrier ABI");
    unsigned char retired_status[56], untouched[56];
    memset(retired_status, 0xa5, sizeof(retired_status)); memcpy(untouched, retired_status, sizeof(untouched));
    CHECK(ioctl(c.control, _IOC(_IOC_READ, 'V', 1, 56), retired_status) == -1 && errno == ENOTTY);
    CHECK(!memcmp(retired_status, untouched, sizeof(untouched)));
    CHECK(ioctl(c.control, SPARKLINK_VIRTUAL_HARDWARE_ERROR, (void *)(uintptr_t)1) == -1 && errno == EFAULT);
    uint32_t code = 256;
    CHECK(ioctl(c.control, SPARKLINK_VIRTUAL_HARDWARE_ERROR, &code) == -1 && errno == EINVAL);
    CHECK(snapshot(c).flags == SLE_CONTROLLER_SETUP);
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        CHECK(!setgroups(0, NULL) && !setgid(1000) && !setuid(1000));
        code = 7;
        CHECK(ioctl(c.control, SPARKLINK_VIRTUAL_HARDWARE_ERROR, &code) == -1 && errno == EPERM);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    CHECK(snapshot(c).flags == SLE_CONTROLLER_SETUP);
    config(c, 1000, 0, 0);
    uint32_t seq[2] = {submit(c, 0x0404), submit(c, 0x0404)};
    pending(c);
    code = 7; CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_HARDWARE_ERROR, &code));
    double deadline = now() + 3;
    struct sle_controller_snapshot snap;
    struct sle_diagnostic_result result;
    for (unsigned i = 0; i < 2; i++) {
        do {
            result = (struct sle_diagnostic_result){.version=1, .generation=c.status.generation, .seq=seq[i]};
            CHECK(!ioctl(c.fd, SL_IOCTL_DIAGNOSTIC_RESULT, &result));
            if (result.state == 3) break;
            CHECK(result.state == 1 && now() < deadline); usleep(1000);
        } while (1);
        CHECK(result.error == -EIO && !result.data_len);
    }
    snap = snapshot(c); CHECK(snap.flags == SLE_CONTROLLER_FAULT && snap.error == -EIO && !snap.command_credits);
    struct sle_mgmt_stats stats;
    CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &stats) && !stats.pending && stats.total_resolved == 2);
    struct sle_diagnostic_submit rejected = {.version=1,.generation=c.status.generation,.request_id=++request_id,.timeout_ms=5000,.opcode=0x0404,.action=1};
    CHECK(ioctl(c.fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &rejected) == -1 && errno == EIO);
    /* A late real backend callback does not repay or reopen the faulted Host. */
    struct sparklink_virtual_status physical;
    do {
        CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_STATUS, &physical));
        if (physical.reply_callbacks_returned) break;
        CHECK(now() < deadline); usleep(1000);
    } while (1);
    CHECK(physical.submitted == 1 && physical.delivered == 1 && physical.reply_callbacks_returned == 1 && !physical.pending);
    code = 8; CHECK(!ioctl(c.control, SPARKLINK_VIRTUAL_HARDWARE_ERROR, &code));
    snap = snapshot(c); CHECK(snap.flags == SLE_CONTROLLER_FAULT && snap.error == -EIO && !snap.command_credits);
    CHECK(!ioctl(c.fd, SL_IOCTL_MGMT_STATS, &stats) && !stats.pending && stats.total_resolved == 2);
    for (unsigned i=0; i<2; i++) {
        result=(struct sle_diagnostic_result){.version=1,.generation=c.status.generation,.seq=seq[i]};
        CHECK(!ioctl(c.fd,SL_IOCTL_DIAGNOSTIC_RESULT,&result) && result.state==3 && result.error==-EIO);
    }
    query(peer, 0x0406, 6);
    CHECK(!close(c.control)); stale(c);
    struct controller replacement = create();
    CHECK(replacement.status.id == c.status.id && replacement.status.generation > c.status.generation);
    query(replacement, 0x0406, 6); stale(c);
    CHECK(!close(replacement.control) && !close(replacement.fd) && !close(c.fd));
    printf("VIRTUAL_HARDWARE_ERROR_PASS: id=%u generation=%llu authors=2 submitted=1 late_reply=ignored callback_return=1 credit=0 inherited_CAP=EPERM invalid=EINVAL bad_pointer=EFAULT retired_status=ENOTTY peer=1 reuse=1 raw_code=7 no_rf=1\n", c.status.id, (unsigned long long)c.status.generation);
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
			if (status.reply_callbacks_returned) break;
			CHECK(now() < deadline);
			usleep(1000);
		} while (1);
		CHECK(snapshot(c).flags == SLE_CONTROLLER_FAULT);
	}
	query(peer, 0x0406, 6);
	CHECK(!close(c.control)); stale(c); CHECK(!close(c.fd));
	printf("VIRTUAL_FAULT: delay=%u drop=%u fail=%u peer_query=1 no_revive=1\n", delay, drop, fail);
}

static void rejected_power(int fd, int ordinary)
{
    const unsigned long commands[] = { SL_IOCTL_PM_INFO, SL_IOCTL_PM_SET_STATE,
        SL_IOCTL_PM_SET_INTERVAL, SL_IOCTL_PM_FORCE_ACTIVE, SL_IOCTL_PM_TICK,
        SL_IOCTL_PM_ACTIVITY };
    for (unsigned i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        unsigned char data[64], original[64]; memset(data, 0xa5, sizeof(data));
        memcpy(original, data, sizeof(data));
        CHECK(ioctl(fd, commands[i], data) == -1);
        CHECK(errno == (ordinary && i ? EPERM : EOPNOTSUPP));
        CHECK(!memcmp(data, original, sizeof(data)));
    }
    printf("VIRTUAL_POWER_UNSUPPORTED_PASS: uid=%u commands=6 unchanged=6\n", getuid());
}

int main(void)
{
	struct controller a = create(), b = create();
	CHECK(a.status.id != b.status.id && a.status.generation != b.status.generation);
	CHECK(!registry_probe(2));
	CHECK(!protocol_state_probe(a.fd));
	rejected_power(a.fd, 0);
    const char *retired_attrs[] = {"max_connections", "adv_interval_ms", "scan_window_ms", "power_mode", "controller_type"};
    for (unsigned i = 0; i < sizeof(retired_attrs)/sizeof(retired_attrs[0]); i++) {
        char path[128]; snprintf(path, sizeof(path), "/sys/kernel/config/sparklink/%s", retired_attrs[i]);
        errno = 0; CHECK(open(path, O_RDWR) == -1 && errno == ENOENT);
    }
    printf("VIRTUAL_GLOBAL_POWER_POLICY_PASS: removed_attrs=5 ENOENT\n");
	fflush(NULL);
	pid_t observer = fork(); CHECK(observer >= 0);
	if (!observer) {
		CHECK(!setgroups(0, NULL) && !setgid(1000) && !setuid(1000));
		CHECK(!protocol_state_probe(a.fd));
		rejected_power(a.fd, 1);
		int result = registry_probe(2); fflush(stdout); _exit(result);
	}
	int status; CHECK(waitpid(observer, &status, 0) == observer && WIFEXITED(status) && !WEXITSTATUS(status));
	standard_snoop(a,b);
	hardware_error_fault(b);
	config(a, 20, 0, 0);
	const uint16_t queries[] = { 0x0401, 0x0402, 0x0403, 0x0404, 0x0406 };
	const unsigned int lengths[] = { 2, 6, 10, 5, 6 };
	for (unsigned int i = 0; i < 5; i++) {
		query(a, queries[i], lengths[i]); query(b, queries[i], lengths[i]);
	}
	release_inflight_queries(b, a);
	b = diagnostic_fd_lifetime(b, a);
	int alias = dup(a.control); CHECK(alias >= 0 && !close(a.control)); a.control = alias;
	query(a, 0x0406, 6);
	struct sparklink_virtual_control bad = { .delay_ms = 6001 };
	CHECK(ioctl(a.control, SPARKLINK_VIRTUAL_CONFIG, &bad) == -1 && errno == EINVAL);
	bad = (struct sparklink_virtual_control){ .drop_next = 33 };
	CHECK(ioctl(a.control, SPARKLINK_VIRTUAL_CONFIG, &bad) == -1 && errno == EINVAL);
	config(a, 6000, 0, 0); submit(a, 0x0404); pending(a);
	double began = now(); CHECK(!close(a.control)); CHECK(now() - began < 1); stale(a); CHECK(!registry_probe(1));
	struct controller replacement = create();
	CHECK(replacement.status.id == a.status.id && replacement.status.generation > a.status.generation);
	CHECK(!registry_probe(2));
	stale(a); query(replacement, 0x0406, 6); query(b, 0x0406, 6);
	CHECK(!close(a.fd));
	fault(0, 1, 0, b); fault(0, 0, 1, b); fault(6000, 0, 0, b);
	CHECK(!close(replacement.control)); CHECK(!close(replacement.fd));
	CHECK(!close(b.control)); CHECK(!close(b.fd));
	CHECK(!registry_probe(0));
	int fd = open("/dev/sparklink", O_RDWR); uint16_t mask = 0xffff;
	CHECK(fd >= 0 && !ioctl(fd, SL_IOCTL_DEV_LIST, &mask) && !mask); close(fd);
	printf("VIRTUAL_RUNTIME_PASS: query=%u dup=1 pending_last_close=1 reuse=1 stale=1 faults=3 empty=1 no_physical=1\n", query_count);
	return 0;
}
