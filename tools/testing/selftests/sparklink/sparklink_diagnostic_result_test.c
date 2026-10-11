// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
/* Opt-in isolated VM only. Real WS73 read-only metadata commands, no event
 * injection or reset. Keep the old fd until the supervisor observes retirement.
 */
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
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
_Static_assert(sizeof(struct sle_diagnostic_submit) == 40, "admission ABI");
_Static_assert(sizeof(struct sle_dli_event) == 256, "legacy event ABI");
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
	uint64_t deadline = now(CLOCK_MONOTONIC) + 6000000000ULL;
	while (ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &r)) {
		require(errno == EAGAIN && !r.lease && now(CLOCK_MONOTONIC) < deadline,
			"Diagnostic acquire"); usleep(10000);
	}
	require(r.lease != 0, "Diagnostic lease token");
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
static struct sle_mgmt_stats stats(int fd)
{
	struct sle_mgmt_stats value = { 0 };
	require(!ioctl(fd, SL_IOCTL_MGMT_STATS, &value), "actual admission counters");
	return value;
}
static struct sle_diagnostic_result completed(int fd, const struct sle_diagnostic_submit *cmd,
					     size_t len, uint64_t deadline)
{
	struct sle_diagnostic_result r;
	for (;;) {
		r = request(cmd->generation, cmd->seq);
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &r), "result query");
		if (r.state != 1) break;
		require(now(CLOCK_MONOTONIC) < deadline, "metadata deadline"); usleep(10000);
	}
	require(r.version == 1 && !r.flags && r.generation == cmd->generation && r.seq == cmd->seq &&
		r.opcode == cmd->opcode && r.state == 2 && !r.error && !r.status && r.data_len == len,
		"exact final reply");
	return r;
}
static void counters(struct sle_mgmt_stats before, struct sle_mgmt_stats after)
{
	printf(",\"submitted_before\":%u,\"submitted_after\":%u,\"resolved_before\":%u,\"resolved_after\":%u,\"pending_before\":%u,\"pending_after\":%u,\"timeouts_before\":%u,\"timeouts_after\":%u",
		before.total_submitted, after.total_submitted, before.total_resolved, after.total_resolved,
		before.pending, after.pending, before.total_timeouts, after.total_timeouts);
}
static struct sle_diagnostic_result query(int fd, uint64_t generation, uint16_t opcode, size_t len)
{
	static uint64_t request_id;
	struct sle_diagnostic_submit initial = { .version = 1, .generation = generation,
		.request_id = ++request_id, .timeout_ms = 5000, .opcode = opcode, .action = 1 };
	struct sle_diagnostic_submit cmd = initial, fault_output = { 0 }, retries[3];
	int fault = opcode == 0x0406 || opcode == 0x0403, error = 0;
	size_t prefix = opcode == 0x0403 ? 36 : 0;
	struct sle_mgmt_stats before = stats(fd);
	require(!before.pending && before.total_submitted != UINT32_MAX &&
		before.total_resolved != UINT32_MAX, "quiet admission accounting");
	uint64_t start = now(CLOCK_REALTIME), deadline = now(CLOCK_MONOTONIC) + 6000000000ULL;
	unsigned char *mapping = NULL, *destination = NULL; long page = 0;
	if (fault) {
		page = sysconf(_SC_PAGESIZE); require(page > 104, "submit page");
		mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		require(mapping != MAP_FAILED, "submit mmap");
		destination = mapping + page - prefix;
		/* A raw ioctl user buffer may be unaligned. Use memcpy, never C struct
		 * dereferences: 36 writable bytes include seq at32, then action faults. */
		memcpy(destination, &initial, sizeof(initial));
		require(!mprotect(mapping + page, page, PROT_READ), "submit readonly suffix");
		errno = 0; int ret = ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, destination); error = errno;
		require(ret == -1 && error == EFAULT, "admission copyout EFAULT");
		memcpy(&fault_output, destination, sizeof(fault_output));
		if (prefix) require(fault_output.seq != 0, "actual partial admission copy includes seq");
		else require(!memcmp(&fault_output, &initial, sizeof(initial)), "readonly submit unchanged");
	}
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &cmd) && cmd.seq, "idempotent metadata admission");
	struct sle_diagnostic_result r = completed(fd, &cmd, len, deadline);
	if (fault) {
		for (size_t i = 0; i < 3; i++) {
			retries[i] = initial;
			require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &retries[i]) &&
				!memcmp(&retries[i], &cmd, sizeof(cmd)), "same ID same admission bytes");
		}
		struct sle_diagnostic_result repeated = request(generation, cmd.seq);
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &repeated) &&
			!memcmp(&repeated, &r, sizeof(r)), "replay result bytes unchanged");
		if (prefix) require(!memcmp(&fault_output, &cmd, prefix), "observed admission copy prefix");
	}
	struct sle_mgmt_stats after = stats(fd);
	require(!after.pending && after.total_submitted == before.total_submitted + 1 &&
		after.total_resolved == before.total_resolved + 1 && after.total_timeouts == before.total_timeouts,
		"one admission one final resolution");
	uint64_t end = now(CLOCK_REALTIME);
	printf("{\"case\":\"metadata\",\"generation\":%llu,\"seq\":%u,\"opcode\":%u,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"data\":",
		(unsigned long long)generation, cmd.seq, opcode, (unsigned long long)start,
		(unsigned long long)end); hex(r.data, r.data_len); puts("}"); fflush(stdout);
	if (fault) {
		printf("{\"admission\":\"%s\",\"result\":-1,\"errno\":%d,\"generation\":%llu,\"request_id\":%llu,\"seq\":%u,\"opcode\":%u,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"partial_prefix\":%zu,\"user_address_mod8\":%zu,\"input\":",
			prefix ? "submit_partial_output" : "submit_read_only_output", error,
			(unsigned long long)generation, (unsigned long long)initial.request_id, cmd.seq, opcode,
			(unsigned long long)start, (unsigned long long)end, prefix, (size_t)((uintptr_t)destination % 8));
		hex(&initial, sizeof(initial)); printf(",\"fault_output\":"); hex(&fault_output, sizeof(fault_output));
		printf(",\"retry_outputs\":[");
		for (size_t i = 0; i < 3; i++) { if (i) putchar(','); hex(&retries[i], sizeof(retries[i])); }
		printf("],\"submitted_before\":%u,\"submitted_after\":%u,\"resolved_before\":%u,\"resolved_after\":%u,\"pending_before\":%u,\"pending_after\":%u,\"timeouts_before\":%u,\"timeouts_after\":%u}\n",
			before.total_submitted, after.total_submitted, before.total_resolved, after.total_resolved,
			before.pending, after.pending, before.total_timeouts, after.total_timeouts); fflush(stdout);
		require(!munmap(mapping, 2 * page), "submit munmap");
	}
	return r;
}
static void legacy_poll_faults(int fd, uint64_t generation, const unsigned char *address)
{
	/* Before Managed/slkd starts, drain this controlled test's stale projection.
	 * Seed each fault with a new actual metadata reply; never synthesize events. */
	struct sle_dli_event discard;
	unsigned int drained = 0;
	for (;;) {
		errno = 0; int ret = ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &discard);
		if (ret == -1) { require(errno == EAGAIN, "legacy drain empty"); break; }
		require(ret == 0 && ++drained <= 31, "bounded legacy drain");
	}
	const char *names[] = { "bad_address", "read_only_output", "partial_output" };
	for (size_t i = 0; i < 3; i++) {
		struct sle_diagnostic_submit input = { .version = 1, .generation = generation,
			.request_id = 5 + i, .timeout_ms = 5000, .opcode = 0x0406, .action = 1 };
		struct sle_diagnostic_submit output = input;
		struct sle_mgmt_stats before = stats(fd);
		require(!before.pending && before.total_submitted != UINT32_MAX &&
			before.total_resolved != UINT32_MAX, "legacy seed quiet accounting");
		uint64_t start = now(CLOCK_REALTIME), deadline = now(CLOCK_MONOTONIC) + 6000000000ULL;
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &output) && output.seq, "real legacy seed submit");
		struct sle_diagnostic_result result = completed(fd, &output, 6, deadline);
		require(!memcmp(result.data, address, 6), "legacy seed actual MAC");
		struct sle_dli_event reference = { .event_type = 1, .opcode = 0x0406, .data_len = 6 };
		memcpy(reference.data, result.data, 6);
		size_t prefix = i == 2 ? 128 : 0;
		unsigned char fault_output[256], *mapping = NULL, *destination = (void *)(uintptr_t)1;
		long page = 0;
		if (i) {
			page = sysconf(_SC_PAGESIZE); require(page > 256, "legacy page");
			mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			require(mapping != MAP_FAILED, "legacy mmap");
			destination = mapping + page - prefix;
			memset(destination, 0xa5, sizeof(fault_output));
			require(!mprotect(mapping + page, page, PROT_READ), "legacy readonly suffix");
		}
		errno = 0; int ret = ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, destination), error = errno;
		require(ret == -1 && error == EFAULT, "legacy actual copy EFAULT");
		if (i) {
			memcpy(fault_output, destination, sizeof(fault_output));
			require(!memcmp(fault_output, &reference, prefix), "legacy actual copied prefix");
			for (size_t j = prefix; j < sizeof(fault_output); j++)
				require(fault_output[j] == 0xa5, "legacy inaccessible suffix unchanged");
		}
		struct sle_dli_event retry;
		memset(&retry, 0x5a, sizeof(retry));
		require(!ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &retry) &&
			!memcmp(&retry, &reference, sizeof(retry)), "legacy retry exact same event");
		errno = 0; int empty = ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &discard), empty_error = errno;
		require(empty == -1 && empty_error == EAGAIN, "legacy consumes only once");
		struct sle_mgmt_stats after = stats(fd);
		require(!after.pending && after.total_submitted == before.total_submitted + 1 &&
			after.total_resolved == before.total_resolved + 1 &&
			after.total_timeouts == before.total_timeouts, "legacy one seed no extra submission");
		uint64_t end = now(CLOCK_REALTIME);
		printf("{\"legacy_poll\":\"%s\",\"generation\":%llu,\"request_id\":%llu,\"seq\":%u,\"opcode\":%u,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"result\":%d,\"errno\":%d,\"partial_prefix\":%zu,\"drained_before\":%u,\"final_poll_result\":%d,\"final_poll_errno\":%d,\"data\":",
			names[i], (unsigned long long)generation, (unsigned long long)input.request_id,
			output.seq, output.opcode, (unsigned long long)start, (unsigned long long)end,
			ret, error, prefix, i ? 0 : drained, empty, empty_error);
		hex(result.data, result.data_len); printf(",\"input\":"); hex(&input, sizeof(input));
		printf(",\"output\":"); hex(&output, sizeof(output));
		printf(",\"result_bytes\":"); hex(&result, sizeof(result));
		printf(",\"reference\":"); hex(&reference, sizeof(reference));
		printf(",\"retry\":"); hex(&retry, sizeof(retry));
		printf(",\"fault_output\":"); if (i) hex(fault_output, sizeof(fault_output)); else printf("null");
		counters(before, after); puts("}"); fflush(stdout);
		if (i) require(!munmap(mapping, 2 * page), "legacy munmap");
	}
}
static void eviction(int fd, uint64_t generation, const unsigned char *address)
{
	/* The separate author fd starts at ID1. Complete each real query before
	 * advancing: 33 completed admissions exceed the actual 32-slot retention. */
	struct sle_diagnostic_submit first = { 0 }, retained = { 0 };
	struct sle_diagnostic_result retained_result = { 0 };
	for (uint64_t id = 1; id <= 33; id++) {
		struct sle_diagnostic_submit input = { .version = 1, .generation = generation,
			.request_id = id, .timeout_ms = 5000, .opcode = 0x0406, .action = 1 };
		struct sle_diagnostic_submit output = input;
		struct sle_mgmt_stats before = stats(fd);
		require(!before.pending && before.total_submitted != UINT32_MAX &&
			before.total_resolved != UINT32_MAX, "quiet eviction fill accounting");
		uint64_t start = now(CLOCK_REALTIME), deadline = now(CLOCK_MONOTONIC) + 6000000000ULL;
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &output) && output.seq, "eviction fill submit");
		struct sle_diagnostic_result result = completed(fd, &output, 6, deadline);
		require(!memcmp(result.data, address, 6), "eviction actual MAC");
		struct sle_mgmt_stats after = stats(fd);
		require(!after.pending && after.total_submitted == before.total_submitted + 1 &&
			after.total_resolved == before.total_resolved + 1 &&
			after.total_timeouts == before.total_timeouts, "eviction one submit one completion");
		uint64_t end = now(CLOCK_REALTIME);
		if (id == 1) first = output;
		if (id == 2) { retained = output; retained_result = result; }
		printf("{\"eviction\":\"fill\",\"generation\":%llu,\"request_id\":%llu,\"seq\":%u,\"opcode\":%u,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"data\":",
			(unsigned long long)generation, (unsigned long long)id, output.seq, output.opcode,
			(unsigned long long)start, (unsigned long long)end);
		hex(result.data, result.data_len); printf(",\"input\":"); hex(&input, sizeof(input));
		printf(",\"output\":"); hex(&output, sizeof(output));
		printf(",\"result_bytes\":"); hex(&result, sizeof(result)); counters(before, after);
		puts("}"); fflush(stdout);
	}
	struct sle_diagnostic_submit old_input = first, retries[3]; old_input.seq = 0;
	int retry_results[3], retry_errnos[3];
	struct sle_mgmt_stats before = stats(fd);
	uint64_t start = now(CLOCK_REALTIME);
	for (size_t i = 0; i < 3; i++) {
		retries[i] = old_input; errno = 0;
		retry_results[i] = ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &retries[i]); retry_errnos[i] = errno;
		require(retry_results[i] == -1 && retry_errnos[i] == ESTALE &&
			!memcmp(&retries[i], &old_input, sizeof(old_input)),
			"evicted ID never resubmits");
	}
	struct sle_diagnostic_result old_query = request(generation, first.seq), old_output = old_query;
	errno = 0; int ret = ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &old_output), error = errno;
	require(ret == -1 && error == ENOENT && !memcmp(&old_output, &old_query, sizeof(old_query)),
		"evicted sequence no longer retained");
	struct sle_diagnostic_submit retained_input = retained, retained_output;
	retained_input.seq = 0; retained_output = retained_input;
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &retained_output) &&
		!memcmp(&retained_output, &retained, sizeof(retained)), "retention boundary ID2 retry");
	struct sle_diagnostic_result repeated = request(generation, retained.seq);
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &repeated) &&
		!memcmp(&repeated, &retained_result, sizeof(repeated)), "retained result bytes");
	/* Observe the quiet Host for100ms as well: an accidentally queued replay
	 * must not escape a short syscall-only capture interval. */
	uint64_t quiet = now(CLOCK_MONOTONIC) + 100000000ULL;
	while (now(CLOCK_MONOTONIC) < quiet) usleep(1000);
	struct sle_mgmt_stats after = stats(fd);
	require(!memcmp(&before, &after, sizeof(before)), "evicted/repeated requests do not change counters");
	uint64_t end = now(CLOCK_REALTIME);
	printf("{\"eviction\":\"old_id_and_result_rejected\",\"generation\":%llu,\"request_id\":1,\"seq\":%u,\"opcode\":%u,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"quiet_observation_ms\":100,\"retry_results\":[%d,%d,%d],\"retry_errnos\":[%d,%d,%d],\"old_input\":",
		(unsigned long long)generation, first.seq, first.opcode, (unsigned long long)start,
		(unsigned long long)end, retry_results[0], retry_results[1], retry_results[2],
		retry_errnos[0], retry_errnos[1], retry_errnos[2]);
	hex(&old_input, sizeof(old_input)); printf(",\"retry_outputs\":[");
	for (size_t i = 0; i < 3; i++) { if (i) putchar(','); hex(&retries[i], sizeof(retries[i])); }
	printf("],\"result_query_return\":%d,\"result_query_errno\":%d,\"result_query_input\":", ret, error);
	hex(&old_query, sizeof(old_query)); printf(",\"result_query_output\":"); hex(&old_output, sizeof(old_output));
	printf(",\"retained_input\":"); hex(&retained_input, sizeof(retained_input));
	printf(",\"retained_output\":"); hex(&retained_output, sizeof(retained_output));
	printf(",\"retained_result\":"); hex(&repeated, sizeof(repeated)); counters(before, after);
	puts("}"); fflush(stdout);
}
static void hold_ack(const char *expected, int timeout_ms)
{
	struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN };
	char ack[32];
	require(poll(&input, 1, timeout_ms) == 1 && (input.revents & POLLIN) &&
		fgets(ack, sizeof(ack), stdin) && !strcmp(ack, expected), "bounded hold acknowledgment");
}
static void hold_phase(const char *phase)
{
	printf("{\"hold_phase\":\"%s\",\"wall_ns\":%llu}\n", phase,
		(unsigned long long)now(CLOCK_REALTIME)); fflush(stdout);
}
static struct sle_diagnostic_result checked_result(int fd,
		const struct sle_diagnostic_submit *cmd, uint32_t state, int error)
{
	struct sle_diagnostic_result r = request(cmd->generation, cmd->seq);
	struct sle_diagnostic_result expected = r;
	expected.opcode = cmd->opcode; expected.state = state; expected.error = error;
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &r) && !memcmp(&r, &expected, sizeof(r)),
		"exact pending or canceled result");
	return r;
}
static struct sle_diagnostic_submit cancel_command(int fd, struct sle_diagnostic_submit cmd)
{
	cmd.seq = 0; cmd.action = 2;
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &cmd) && cmd.seq, "cancel retains admission");
	return cmd;
}
struct deadline_sample {
	uint64_t before, after;
	struct sle_diagnostic_submit retry;
	struct sle_diagnostic_result result;
};
#define DEADLINE_SAMPLES 512
static void print_deadline(const struct sle_diagnostic_submit *input,
	const struct sle_diagnostic_submit *output, const struct sle_diagnostic_result *initial,
	uint64_t before, uint64_t after, const struct deadline_sample *samples, unsigned count)
{
	printf(",\"deadline\":{\"input\":"); hex(input, sizeof(*input));
	printf(",\"output\":"); hex(output, sizeof(*output));
	printf(",\"initial_result\":"); hex(initial, sizeof(*initial));
	printf(",\"admit_before_monotonic_ns\":%llu,\"admit_after_monotonic_ns\":%llu,\"samples\":[",
		(unsigned long long)before, (unsigned long long)after);
	for (unsigned i = 0; i < count; ++i) {
		if (i) putchar(',');
		printf("{\"before_monotonic_ns\":%llu,\"after_monotonic_ns\":%llu,\"retry\":",
			(unsigned long long)samples[i].before, (unsigned long long)samples[i].after);
		hex(&samples[i].retry, sizeof(samples[i].retry)); printf(",\"result\":");
		hex(&samples[i].result, sizeof(samples[i].result)); putchar('}');
	}
	printf("]}");
}
static void cancel_held(int fd, uint64_t generation, const unsigned char *address, int deadline_test)
{
	/* QMP holds an actual successful host transfer; guest never injects data. */
	hold_phase("arm_ready"); hold_ack("armed\n", 10000);
	struct sle_mgmt_stats before = stats(fd);
	struct sle_diagnostic_submit input[3], output[3], canceled[2];
	uint64_t start = now(CLOCK_REALTIME);
	for (size_t i = 0; i < 3; i++) {
		input[i] = (struct sle_diagnostic_submit){ .version = 1, .generation = generation,
			.request_id = 8+i, .timeout_ms = 5000, .opcode = i == 2 ? 0x0403 : 0x0406, .action = 1 };
		output[i] = input[i];
	}
	require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &output[0]) && output[0].seq, "held MAC admission");
	checked_result(fd, &output[0], 1, 0);
	hold_phase("wait_held"); hold_ack("held\n", 5000);
	checked_result(fd, &output[0], 1, 0);
	canceled[0] = cancel_command(fd, output[0]);
	require(canceled[0].seq == output[0].seq, "active cancel same sequence");
	for (size_t i = 1; i < 3; i++)
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &output[i]) &&
			output[i].seq == output[i-1].seq+1, "FIFO queued admission");
	checked_result(fd, &output[2], 1, 0);
	canceled[1] = cancel_command(fd, output[2]);
	require(canceled[1].seq == output[2].seq, "queued cancel same sequence");
	struct sle_diagnostic_result active = checked_result(fd, &output[0], 3, -ECANCELED);
	struct sle_diagnostic_result queued = checked_result(fd, &output[2], 3, -ECANCELED), pending;
	struct sle_diagnostic_submit deadline_input = { .version = 1, .generation = generation,
		.request_id = 11, .timeout_ms = 100, .opcode = 0x0403, .action = 1 };
	struct sle_diagnostic_submit deadline_output = deadline_input;
	struct sle_diagnostic_result deadline_initial = { 0 }, deadline_final = { 0 };
	struct deadline_sample samples[DEADLINE_SAMPLES]; unsigned sample_count = 0;
	uint64_t admit_before = 0, admit_after = 0, expired_after = 0;
	uint64_t quiet_start = now(CLOCK_MONOTONIC), quiet_end = quiet_start + (deadline_test ? 150000000ULL : 50000000ULL);
	if (deadline_test) {
		admit_before = now(CLOCK_MONOTONIC);
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &deadline_output) && deadline_output.seq == output[2].seq+1,
			"expiring queued admission");
		admit_after = now(CLOCK_MONOTONIC);
		deadline_initial = checked_result(fd, &deadline_output, 1, 0);
	}
	unsigned observations = 0;
	do {
		pending = checked_result(fd, &output[1], 1, 0);
		checked_result(fd, &output[0], 3, -ECANCELED); checked_result(fd, &output[2], 3, -ECANCELED);
		for (size_t i = 0; i < 3; i++) {
			struct sle_diagnostic_submit retry = input[i];
			require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &retry) &&
				!memcmp(&retry, &output[i], sizeof(retry)), "held ID retry unchanged");
		}
		for (size_t i = 0; i < 2; i++) {
			struct sle_diagnostic_submit retry = cancel_command(fd, output[i ? 2 : 0]);
			require(!memcmp(&retry, &canceled[i], sizeof(retry)), "repeated cancel unchanged");
		}
		if (deadline_test) {
			require(sample_count < DEADLINE_SAMPLES, "bounded original deadline observations");
			struct deadline_sample *sample = &samples[sample_count++];
			sample->before = now(CLOCK_MONOTONIC); sample->retry = deadline_input;
			require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &sample->retry) &&
				!memcmp(&sample->retry, &deadline_output, sizeof(sample->retry)), "deadline ID retry unchanged");
			sample->result = request(generation, deadline_output.seq);
			require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &sample->result), "queued deadline result");
			sample->after = now(CLOCK_MONOTONIC);
			if (sample->result.state == 1) {
				require(!expired_after && !memcmp(&sample->result, &deadline_initial, sizeof(sample->result)),
					"original pending result does not revive");
			} else {
				deadline_final = checked_result(fd, &deadline_output, 3, -ETIMEDOUT);
				require(!memcmp(&sample->result, &deadline_final, sizeof(sample->result)), "exact single queued timeout");
				if (!expired_after) expired_after = sample->after;
			}
		}
		observations++; usleep(1000);
	} while (now(CLOCK_MONOTONIC) < quiet_end);
	struct sle_mgmt_stats held = stats(fd);
	require(held.total_submitted == before.total_submitted+3+deadline_test && held.total_resolved == before.total_resolved+2+deadline_test &&
		!before.pending && held.pending == 1 && held.total_timeouts == before.total_timeouts+deadline_test,
		"held cancel and replay accounting");
	if (deadline_test) require(expired_after && expired_after >= admit_before+75000000ULL &&
		expired_after <= admit_after+180000000ULL && sample_count >= 10, "original deadline not renewed by retries");
	uint64_t held_end = now(CLOCK_REALTIME);
	printf("{\"cancel\":\"held\",\"generation\":%llu,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"quiet_elapsed_ns\":%llu,\"observations\":%u,\"inputs\":[",
		(unsigned long long)generation, (unsigned long long)start, (unsigned long long)held_end,
		(unsigned long long)(now(CLOCK_MONOTONIC)-quiet_start), observations);
	for (size_t i = 0; i < 3; i++) { if (i) putchar(','); hex(&input[i], sizeof(input[i])); }
	printf("],\"outputs\":[");
	for (size_t i = 0; i < 3; i++) { if (i) putchar(','); hex(&output[i], sizeof(output[i])); }
	printf("],\"cancel_outputs\":["); hex(&canceled[0], sizeof(canceled[0])); putchar(','); hex(&canceled[1], sizeof(canceled[1]));
	printf("],\"results\":["); hex(&active, sizeof(active)); putchar(','); hex(&pending, sizeof(pending)); putchar(','); hex(&queued, sizeof(queued));
	putchar(']'); counters(before, held);
	if (deadline_test) print_deadline(&deadline_input, &deadline_output, &deadline_initial,
		admit_before, admit_after, samples, sample_count);
	puts("}"); fflush(stdout);
	hold_phase("release_ready"); hold_ack("released\n", 1500);
	struct sle_diagnostic_result final = completed(fd, &output[1], 6, now(CLOCK_MONOTONIC)+6000000000ULL);
	require(!memcmp(final.data, address, 6), "fresh MAC reply");
	uint64_t quiet = now(CLOCK_MONOTONIC)+100000000ULL;
	do {
		checked_result(fd, &output[0], 3, -ECANCELED); checked_result(fd, &output[2], 3, -ECANCELED);
		if (deadline_test) {
			struct sle_diagnostic_submit retry = deadline_input;
			require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &retry) &&
				!memcmp(&retry, &deadline_output, sizeof(retry)), "expired ID does not readmit after release");
			checked_result(fd, &deadline_output, 3, -ETIMEDOUT);
		}
		struct sle_diagnostic_result retry = request(generation, output[1].seq);
		require(!ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &retry) && !memcmp(&retry, &final, sizeof(retry)), "fresh final stable");
		usleep(1000);
	} while (now(CLOCK_MONOTONIC) < quiet);
	struct sle_mgmt_stats after = stats(fd);
	require(after.total_submitted == held.total_submitted && after.total_resolved == held.total_resolved+1 &&
		!after.pending && after.total_timeouts == held.total_timeouts, "release resolves only fresh request");
	printf("{\"cancel\":\"released\",\"generation\":%llu,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"results\":[",
		(unsigned long long)generation, (unsigned long long)held_end, (unsigned long long)now(CLOCK_REALTIME));
	hex(&active, sizeof(active)); putchar(','); hex(&final, sizeof(final)); putchar(','); hex(&queued, sizeof(queued));
	putchar(']'); counters(held, after);
	if (deadline_test) { printf(",\"deadline\":{\"result\":"); hex(&deadline_final, sizeof(deadline_final)); printf("}"); }
	puts("}"); fflush(stdout);
}
/* Removed commands remain literal only in rejection tests. No compatibility
 * binding or production injection is retained. stderr keeps this separate from
 * the historical diagnostic result/admission formats. */
static void retired_registration(int fd, uint64_t generation)
{
	const unsigned long commands[] = { 0x00005301, 0x40025302, 0x40045302 };
	struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
	struct __user_cap_data_struct c[2] = { 0 };
	struct sle_controller_snapshot before = { .version = 1, .generation = generation };
	struct sle_controller_snapshot after = before;
	struct sle_mgmt_stats stats_before = stats(fd);
	__u16 mask_before = 0, mask_after = 0;
	int count_before = ioctl(fd, SL_IOCTL_DEV_COUNT, NULL);
	require(count_before > 0 && !ioctl(fd, SL_IOCTL_DEV_LIST, &mask_before) &&
		!ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &before) &&
		!syscall(SYS_capget, &h, c), "retired ABI observation before");
	uint64_t start = now(CLOCK_REALTIME);
	for (unsigned i = 0; i < sizeof(commands)/sizeof(commands[0]); ++i) {
		for (unsigned j = 0; j < 3; ++j) {
			unsigned char sentinel[8], reference[8];
			memset(sentinel, 0xa5, sizeof(sentinel)); memcpy(reference, sentinel, sizeof(reference));
			void *argument = j == 0 ? NULL : j == 1 ? (void *)1 : sentinel;
			errno = 0;
			int result = ioctl(fd, commands[i], argument);
			require(result == -1 && errno == ENOTTY &&
				!memcmp(sentinel, reference, sizeof(sentinel)), "retired registration rejected before usercopy");
		}
	}
	uint64_t end = now(CLOCK_REALTIME);
	struct sle_mgmt_stats stats_after = stats(fd);
	require(ioctl(fd, SL_IOCTL_DEV_COUNT, NULL) == count_before &&
		!ioctl(fd, SL_IOCTL_DEV_LIST, &mask_after) && mask_after == mask_before &&
		!ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &after) &&
		!memcmp(&before, &after, sizeof(before)) &&
		!memcmp(&stats_before, &stats_after, sizeof(stats_before)), "retired registration changes no state");
	fprintf(stderr, "RETIRED_REGISTRATION_PASS {\"uid\":%u,\"euid\":%u,\"cap_eff\":%llu,\"cap_prm\":%llu,\"generation\":%llu,\"cases\":9,\"errno\":%d,\"unchanged\":true,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu}\n",
		getuid(), geteuid(), (unsigned long long)c[0].effective | (unsigned long long)c[1].effective << 32,
		(unsigned long long)c[0].permitted | (unsigned long long)c[1].permitted << 32,
		(unsigned long long)generation, ENOTTY, (unsigned long long)start, (unsigned long long)end);
	fflush(stderr);
}
static void retired_registration_root_cap0(int fd, uint64_t generation)
{
	pid_t child = fork(); require(child >= 0, "root capability-drop fork");
	if (!child) {
		struct __user_cap_header_struct h = { .version = _LINUX_CAPABILITY_VERSION_3 };
		struct __user_cap_data_struct c[2] = { 0 };
		require(!setgroups(0, NULL) && !syscall(SYS_capset, &h, c), "root zero capability set");
		retired_registration(fd, generation); _exit(0);
	}
	int status;
	require(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status), "root capability-drop exit");
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
		retired_registration(fd, generation);
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
	int deadline_test = argc == 3 && !strcmp(argv[2], "deadline");
	int cancellation = deadline_test || (argc == 3 && !strcmp(argv[2], "cancel"));
	require((argc == 2 || cancellation) && (!cancellation || strstr(cmdline, "ws73.diagnostic_cancel=1")) &&
		(!deadline_test || strstr(cmdline, "ws73.diagnostic_deadline=1")) &&
		!getuid() && !geteuid() && !stat("/scratch-root-uuid", &s) &&
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
	retired_registration(fd, generation);
	retired_registration_root_cap0(fd, generation);
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
	legacy_poll_faults(fd, generation, snapshot.address);
	if (cancellation) cancel_held(fd, generation, snapshot.address, deadline_test);
	release(fd, &lease);
	int other = bound(index); lease = acquire(other, generation);
	rejected(other, "foreign_author_with_lease", request(generation, mac.seq), EPERM);
	eviction(other, generation, snapshot.address);
	release(other, &lease); close(other);
	puts("{\"phase\":\"BEFORE_DAEMON_PASS\"}"); fflush(stdout);
	char ack[32]; require(fgets(ack, sizeof(ack), stdin) && !strcmp(ack, "retired\n"), "retirement acknowledgment");
	rejected(fd, "retired_fd", request(generation, mac.seq), ENODEV);
	close(fd); puts("{\"phase\":\"DIAGNOSTIC_RESULT_LIVE_PASS\"}"); fflush(stdout);
	return 0;
}
