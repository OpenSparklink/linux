// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
/* Opt-in isolated VM only. Real WS73 read-only metadata commands, no event
 * injection or reset. Keep the old fd until the supervisor observes retirement.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"

_Static_assert(sizeof(struct sle_diagnostic_result) == 104, "diagnostic ABI");
static void require(int ok, const char *message)
{
	if (!ok) { fprintf(stderr, "DIAGNOSTIC_RESULT_FAILURE: %s errno=%d\n", message, errno); exit(1); }
}
static uint64_t now(clockid_t clock)
{
	struct timespec t;
	require(!clock_gettime(clock, &t), "clock");
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static void hex(const void *p, size_t n)
{
	const unsigned char *b = p;
	putchar('"'); for (size_t i = 0; i < n; i++) printf("%02x", b[i]); putchar('"');
}
static struct sle_diagnostic_result request(uint64_t generation, uint32_t seq)
{
	return (struct sle_diagnostic_result){ .version = 1, .generation = generation, .seq = seq };
}
static void rejected(int fd, const char *name, struct sle_diagnostic_result value, int expected)
{
	struct sle_diagnostic_result before = value;
	errno = 0; int ret = ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &value), error = errno;
	require(ret == -1 && error == expected && !memcmp(&before, &value, sizeof(value)), name);
	printf("{\"case\":\"%s\",\"result\":%d,\"errno\":%d}\n", name, ret, error); fflush(stdout);
}
static int bound(uint16_t index)
{
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	require(fd >= 0, "open");
	uint64_t deadline = now(CLOCK_MONOTONIC) + 90000000000ULL;
	while (ioctl(fd, SL_IOCTL_DEV_SELECT, &index)) {
		require(errno == ENODEV && now(CLOCK_MONOTONIC) < deadline, "selected fd"); usleep(10000);
	}
	return fd;
}
static struct sle_management_request acquire(int fd, uint64_t generation)
{
	struct sle_management_request r = { .version = 1, .generation = generation, .mode = 2 };
	require(!ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &r) && r.lease, "Diagnostic acquire");
	return r;
}
static void release(int fd, struct sle_management_request *r)
{
	require(!ioctl(fd, SL_IOCTL_MANAGEMENT_RELEASE, r), "Diagnostic release");
	uint64_t deadline = now(CLOCK_MONOTONIC) + 6000000000ULL;
	for (;;) {
		struct sle_management_query q = { .version = 1, .generation = r->generation };
		require(!ioctl(fd, SL_IOCTL_MANAGEMENT_QUERY, &q), "release query");
		if (q.state == 0) break;
		require(now(CLOCK_MONOTONIC) < deadline && q.state == 2, "release settles Free");
		usleep(10000);
	}
}
static struct sle_diagnostic_result query(int fd, uint64_t generation, uint16_t opcode, size_t len)
{
	struct sle_dli_cmd cmd = { .opcode = opcode };
	uint64_t start = now(CLOCK_REALTIME), deadline = now(CLOCK_MONOTONIC) + 6000000000ULL;
	require(!ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &cmd) && cmd.seq, "raw metadata admission");
	struct sle_diagnostic_result r;
	for (;;) {
		r = request(generation, cmd.seq);
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &r), "result query");
		if (r.state != 1) break;
		require(now(CLOCK_MONOTONIC) < deadline, "metadata deadline"); usleep(10000);
	}
	require(r.version == 1 && !r.flags && r.generation == generation && r.seq == cmd.seq &&
		r.opcode == opcode && r.state == 2 && !r.error && !r.status && r.data_len == len, "exact final reply");
	printf("{\"case\":\"metadata\",\"generation\":%llu,\"seq\":%u,\"opcode\":%u,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"data\":",
		(unsigned long long)generation, cmd.seq, opcode, (unsigned long long)start,
		(unsigned long long)now(CLOCK_REALTIME)); hex(r.data, r.data_len); puts("}"); fflush(stdout);
	return r;
}
static void caps_zero(int fd, uint64_t generation, uint32_t seq)
{
	fflush(stdout); pid_t pid = fork(); require(pid >= 0, "fork");
	if (!pid) {
		struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
		struct __user_cap_data_struct c[2] = { 0 };
		require(!setgroups(0, NULL) && !setresgid(1000, 1000, 1000) &&
			!setresuid(1000, 1000, 1000), "ordinary inherited fd child");
		require(!syscall(SYS_capset, &h, c) && !syscall(SYS_capget, &h, c), "child caps");
		require(!c[0].effective && !c[1].effective && !c[0].permitted && !c[1].permitted,
			"actual child capabilities zero");
		printf("{\"identity\":\"inherited_fd_child\",\"uid\":%u,\"euid\":%u,\"cap_eff\":0,\"cap_prm\":0}\n", getuid(), geteuid());
		rejected(fd, "inherited_fd_cap0", request(generation, seq), EPERM); _exit(0);
	}
	int status; require(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status), "CAP child exit");
}
static void copy_fault(int fd, const char *name, const struct sle_diagnostic_result *reference, int partial)
{
	long page = sysconf(_SC_PAGESIZE); require(page > 104, "page");
	unsigned char *p = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	require(p != MAP_FAILED, "mmap");
	size_t prefix = partial ? (sizeof(*reference) / 2 + 7) & ~(size_t)7 : 0;
	struct sle_diagnostic_result *destination = (void *)(p + page - prefix);
	*destination = request(reference->generation, reference->seq);
	require(!mprotect(p + page, page, PROT_READ), "readable unwritable output");
	errno = 0; int ret = ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, destination), error = errno;
	require(ret == -1 && error == EFAULT, "copyout EFAULT");
	if (partial) require(destination->state == 2 && !memcmp(destination, reference, prefix), "observed partial copy");
	struct sle_diagnostic_result retry = request(reference->generation, reference->seq);
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &retry) && !memcmp(&retry, reference, sizeof(retry)), "byte exact retry");
	printf("{\"case\":\"%s\",\"result\":%d,\"errno\":%d,\"partial_prefix\":%zu,\"reference\":", name, ret, error, prefix);
	hex(reference, sizeof(*reference)); printf(",\"retry\":"); hex(&retry, sizeof(retry)); puts("}"); fflush(stdout);
	require(!munmap(p, 2 * page), "munmap");
}
int main(int argc, char **argv)
{
	char cmdline[4096] = { 0 }, *end; struct stat s;
	FILE *f = fopen("/proc/cmdline", "r"); require(f && fgets(cmdline, sizeof(cmdline), f), "cmdline"); fclose(f);
	require(argc == 2 && !getuid() && !geteuid() && !stat("/scratch-root-uuid", &s) &&
		strstr(cmdline, "ws73.diagnostic=1"), "opt-in scratch-root VM only");
	long index = strtol(argv[1], &end, 10); require(*argv[1] && !*end && index >= 0 && index < 16, "index");
	int fd = bound(index);
	struct sle_controller_snapshot snapshot = { .version = 1 };
	uint64_t deadline = now(CLOCK_MONOTONIC) + 90000000000ULL;
	for (;;) {
		snapshot.flags = 0; /* Output flags are not valid query-input flags. */
		require(!ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &snapshot), "snapshot");
		/* Diagnostics precede Managed radio initialization. Metadata availability
		 * is sufficient; do not pretend Setup has confirmed radio Off/Ready. */
		if ((snapshot.flags == SLE_CONTROLLER_SETUP || snapshot.flags == SLE_CONTROLLER_READY) &&
		    snapshot.profile == 1 && snapshot.valid_fields == SLE_CONTROLLER_FULL_METADATA && !snapshot.error) break;
		require(snapshot.flags != SLE_CONTROLLER_FAULT && now(CLOCK_MONOTONIC) < deadline,
			"metadata availability deadline"); usleep(10000);
	}
	uint64_t generation = snapshot.generation;
	struct sle_management_request lease = acquire(fd, generation);
	struct sle_diagnostic_result mac = query(fd, generation, 0x0406, 6);
	require(!memcmp(mac.data, snapshot.address, 6), "metadata address");
	struct sle_diagnostic_result features = query(fd, generation, 0x0403, 10);
	require(!memcmp(features.data, snapshot.features, 10), "metadata features");
	struct sle_diagnostic_result version = query(fd, generation, 0x0404, 5);
	require(!memcmp(version.data, snapshot.version_tuple, 5), "metadata version");
	struct sle_diagnostic_result buffers = query(fd, generation, 0x0402, 6);
	unsigned char expected[] = { snapshot.acb_length & 0xff, snapshot.acb_length >> 8, snapshot.acb_count,
		snapshot.icb_length & 0xff, snapshot.icb_length >> 8, snapshot.icb_count };
	require(!memcmp(buffers.data, expected, sizeof(expected)), "metadata buffers");
	caps_zero(fd, generation, mac.seq);
	copy_fault(fd, "read_only_output", &mac, 0); copy_fault(fd, "partial_output", &mac, 1);
	struct sle_diagnostic_result bad = request(generation, mac.seq);
	bad.version = 2; rejected(fd, "version", bad, EOPNOTSUPP);
	bad = request(generation, mac.seq); bad.flags = 1; rejected(fd, "flags", bad, EINVAL);
	bad = request(generation, mac.seq); bad._reserved[0] = 1; rejected(fd, "reserved", bad, EINVAL);
	bad = request(generation, mac.seq); bad.seq = 0; rejected(fd, "zero_seq", bad, EINVAL);
	bad = request(generation, mac.seq); bad.generation = 0; rejected(fd, "zero_generation", bad, EINVAL);
	rejected(fd, "wrong_generation", request(generation + 1, mac.seq), ENODEV);
	rejected(fd, "missing_sequence", request(generation, UINT32_MAX), ENOENT);
	release(fd, &lease);
	int other = bound(index); lease = acquire(other, generation);
	rejected(other, "foreign_author_with_lease", request(generation, mac.seq), EPERM);
	release(other, &lease); close(other);
	puts("{\"phase\":\"BEFORE_DAEMON_PASS\"}"); fflush(stdout);
	char ack[32]; require(fgets(ack, sizeof(ack), stdin) && !strcmp(ack, "retired\n"), "retirement acknowledgment");
	rejected(fd, "retired_fd", request(generation, mac.seq), ENODEV);
	close(fd); puts("{\"phase\":\"DIAGNOSTIC_RESULT_LIVE_PASS\"}"); fflush(stdout);
	return 0;
}
