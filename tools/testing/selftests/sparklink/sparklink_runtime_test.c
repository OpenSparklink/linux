// SPDX-License-Identifier: GPL-2.0
/* Kernel Runtime lifetime support test using two virtual DLI controllers.
 * The host runner performs the requested QMP hotplug operations. This is not
 * WS73/RF, slkd dynamic-adapter, or unprivileged-application evidence.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"

static int failed;

static int fail(const char *message)
{
	fprintf(stderr, "RUNTIME_FAILURE: %s (errno=%d)\n", message, errno);
	failed = 1;
	return -1;
}

static double now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		exit(EXIT_FAILURE);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static int wait_mask(int fd, uint16_t expected)
{
	double deadline = now() + 10;

	while (now() < deadline) {
		uint16_t mask = 0;

		if (ioctl(fd, SL_IOCTL_DEV_LIST, &mask) < 0)
			return fail("DEV_LIST");
		if (mask == expected)
			return 0;
		usleep(10000);
	}
	return fail("registration mask deadline");
}

static int bind_adapter(int id, struct sci_dev_info *info)
{
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	int16_t target = id;
	double deadline = now() + 10;

	if (fd < 0)
		return fail("open adapter");
	/* Registration precedes asynchronous probe/Runtime publication. Require
	 * usable control within a deadline; a registry bit alone is not Ready. */
	while (now() < deadline) {
		if (ioctl(fd, SL_IOCTL_DEV_SELECT, &target) == 0 &&
		    ioctl(fd, SL_IOCTL_DEV_INFO, info) == 0) {
			if (info->index == id)
				return fd;
			close(fd);
			return fail("adapter index mismatch");
		}
		if (errno != ENODEV)
			break;
		usleep(10000);
	}
	close(fd);
	return fail("bind/query adapter deadline");
}

static int same_adapter(int fd, const struct sci_dev_info *expected)
{
	struct sci_dev_info info = { 0 };

	if (ioctl(fd, SL_IOCTL_DEV_INFO, &info) < 0 ||
	    info.index != expected->index || memcmp(info.addr, expected->addr, 6))
		return fail("unaffected adapter identity");
	return 0;
}

static int stale_adapter(int fd)
{
	struct sci_dev_info info = { 0 };

	errno = 0;
	if (ioctl(fd, SL_IOCTL_DEV_INFO, &info) != -1 || errno != ENODEV)
		return fail("old fd must return ENODEV");
	return 0;
}

static int query_mac(int fd, const struct sci_dev_info *info)
{
	struct sle_mgmt_stats before = { 0 }, after = { 0 };
	struct sle_dli_cmd command = { .opcode = 0x0406 };
	double deadline = now() + 10;
	int received = 0;

	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &before) < 0 || before.pending)
		return fail("query requires quiet command baseline");
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &command) < 0)
		return fail("submit ReadMacAddr");
	while (now() < deadline) {
		struct sle_dli_event event = { 0 };

		if (ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &event) == 0) {
			if (event.opcode == 0x0406 && event.event_type == 1) {
				if (event.status || event.data_len != 6 ||
				    memcmp(event.data, info->addr, 6))
					return fail("ReadMacAddr reply mismatch");
				received = 1;
				break;
			}
		} else if (errno != EAGAIN) {
			return fail("poll ReadMacAddr");
		}
		usleep(1000);
	}
	if (!received || ioctl(fd, SL_IOCTL_MGMT_STATS, &after) < 0 ||
	    after.pending || after.total_submitted != before.total_submitted + 1 ||
	    after.total_resolved != before.total_resolved + 1 ||
	    after.total_timeouts != before.total_timeouts)
		return fail("ReadMacAddr transaction/count deadline");
	printf("RUNTIME_QUERY: index=%u addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
	       info->index, info->addr[0], info->addr[1], info->addr[2],
	       info->addr[3], info->addr[4], info->addr[5]);
	return 0;
}

/* Mix a typed internal Reset with raw Reset and repeated identical opcodes.
 * Check every report and exact raw counters independently on both owners. */
static int burst_queries(int fd, const struct sci_dev_info *info)
{
	struct sle_mgmt_stats before = { 0 }, after = { 0 };
	int mac = 0, reset = 0;
	double deadline = now() + 4;

	for (int n = 0; n < 256; n++) {
		struct sle_dli_event event = { 0 };

		if (ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &event) < 0) {
			if (errno != EAGAIN)
				return fail("burst drain");
			break;
		}
	}
	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &before) < 0 || before.pending)
		return fail("burst quiet baseline");
	if (ioctl(fd, SL_IOCTL_DLI_RESET, 0) < 0)
		return fail("burst typed Reset");
	for (int n = 0; n < 13; n++) {
		struct sle_dli_cmd command = { .opcode = n ? 0x0406 : 0x0408 };

		if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &command) < 0 || !command.seq)
			return fail("burst raw submission");
	}
	while (now() < deadline && (mac < 12 || reset < 2)) {
		struct sle_dli_event event = { 0 };

		if (ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &event) == 0) {
			if (event.event_type != 1)
				continue;
			if (event.opcode == 0x0406) {
				if (event.status || event.data_len != 6 ||
				    memcmp(event.data, info->addr, 6))
					return fail("burst MAC belongs to another owner or failed");
				mac++;
			} else if (event.opcode == 0x0408) {
				if (event.status || event.data_len)
					return fail("burst Reset reply");
				reset++;
			} else {
				return fail("unexpected burst command reply");
			}
		} else if (errno != EAGAIN) {
			return fail("burst poll");
		}
		usleep(1000);
	}
	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &after) < 0)
		return fail("burst final stats");
	printf("RUNTIME_HOST_COUNTS: index=%u mac=%d reset=%d pending=%u submitted=%u resolved=%u timeouts=%u\n",
	       info->index, mac, reset, after.pending,
	       after.total_submitted - before.total_submitted,
	       after.total_resolved - before.total_resolved,
	       after.total_timeouts - before.total_timeouts);
	if (mac != 12 || reset != 2 ||
	    after.pending || after.total_submitted != before.total_submitted + 13 ||
	    after.total_resolved != before.total_resolved + 13 ||
	    after.total_timeouts != before.total_timeouts)
		return fail("burst reports/counts/deadline");
	printf("RUNTIME_HOST_BURST: index=%u mac=12 reset=2 submitted=13 resolved=13 timeouts=0\n",
	       info->index);
	return 0;
}

static int parallel_bursts(int a, const struct sci_dev_info *info_a,
			   int b, const struct sci_dev_info *info_b)
{
	int fds[2] = { a, b };
	const struct sci_dev_info *infos[2] = { info_a, info_b };
	pid_t children[2];

	for (int i = 0; i < 2; i++) {
		children[i] = fork();
		if (!children[i])
			exit(burst_queries(fds[i], infos[i]) < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
	}
	for (int i = 0; i < 2; i++) {
		int status = 0;

		if (children[i] < 0 || waitpid(children[i], &status, 0) != children[i] ||
		    !WIFEXITED(status) || WEXITSTATUS(status))
			failed = 1;
	}
	return failed ? fail("parallel Host bursts") : 0;
}

/* Standard USB one-step typed recipes only. The model grants credit in
 * Status, delays Complete by 25 ms and aborts on a premature next command.
 * No native WS73 multi-step recipe, RF or slctl acceptance is inferred.
 */
static int recipe_control(int fd, const struct sci_dev_info *info, unsigned int operation)
{
	struct sle_dli_cmd query = { .opcode = 0x0406 };
	struct sle_adv_params adv = { .dev_index = info->index, .interval_ms = 50, .discovery_level = 1 };
	struct sle_scan_params scan = { .dev_index = info->index, .window_ms = 25, .interval_ms = 50 };
	uint8_t role = operation < 2 ? 1 : 0;
	unsigned int opcode = operation < 2 ? 0x0c05 : 0x1002;
	int status = 0, complete = 0, mac = 0, result;
	double deadline = now() + 5;

	if (!(operation & 1) && ioctl(fd, SL_IOCTL_SET_ROLE, &role))
		return fail("recipe role");
	switch (operation) {
	case 0: result = ioctl(fd, SL_IOCTL_START_ADV, &adv); break;
	case 1: result = ioctl(fd, SL_IOCTL_STOP_ADV, 0); break;
	case 2: result = ioctl(fd, SL_IOCTL_START_SCAN, &scan); break;
	default: result = ioctl(fd, SL_IOCTL_STOP_SCAN, 0); break;
	}
	if (result || ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &query) || !query.seq)
		return fail("typed recipe and queued raw query");
	while (now() < deadline && (!complete || !mac)) {
		struct sle_dli_event event = { 0 };

		if (!ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &event)) {
			if (event.opcode == opcode && event.event_type == 2) {
				if (event.status || complete || status++)
					return fail("recipe acceptance order/count/status");
			} else if (event.opcode == opcode && event.event_type == 1) {
				if (event.status || event.data_len || status != 1 || complete++)
					return fail("recipe Complete order/count/status");
			} else if (event.opcode == 0x0406 && event.event_type == 1) {
				if (event.status || event.data_len != 6 || complete != 1 || mac++ ||
				    memcmp(event.data, info->addr, 6))
					return fail("recipe next command/owner/order");
			}
		} else if (errno != EAGAIN) {
			return fail("recipe event poll");
		}
		usleep(1000);
	}
	return status == 1 && complete == 1 && mac == 1 ? 0 : fail("recipe reply deadline");
}

static int typed_recipes(int fd, const struct sci_dev_info *info)
{
	struct sle_mgmt_stats before, after;

	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &before) || before.pending)
		return fail("recipe quiet baseline");
	for (unsigned int operation = 0; operation < 4; operation++)
		if (recipe_control(fd, info, operation))
			return -1;
	if (ioctl(fd, SL_IOCTL_MGMT_STATS, &after) || after.pending ||
	    after.total_submitted != before.total_submitted + 4 ||
	    after.total_resolved != before.total_resolved + 4 ||
	    after.total_timeouts != before.total_timeouts)
		return fail("recipe raw query accounting");
	printf("RUNTIME_RECIPE: index=%u adv_complete=2 scan_complete=2 status=4 mac=4 isolated=1\n", info->index);
	return 0;
}

int main(int argc, char **argv)
{
	int control = -1, a = -1, b = -1, replacement = -1;
	struct sci_dev_info info_a = { 0 }, info_b = { 0 }, info_new = { 0 };
	int recipe_mode = argc == 2 && !strcmp(argv[1], "--recipes");
	if (argc != 1 && !recipe_mode)
		return 2;

	setvbuf(stdout, NULL, _IOLBF, 0);
	control = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	if (control < 0 || wait_mask(control, 1) < 0)
		goto out;
	a = bind_adapter(0, &info_a);
	if (a < 0 || query_mac(a, &info_a) < 0)
		goto out;
	puts("RUNTIME_ADD_SECOND");
	if (wait_mask(control, 3) < 0)
		goto out;
	b = bind_adapter(1, &info_b);
	if (b < 0 || query_mac(b, &info_b) < 0 || same_adapter(a, &info_a) < 0)
		goto out;
	if (parallel_bursts(a, &info_a, b, &info_b) < 0)
		goto out;
	if (recipe_mode && (typed_recipes(a, &info_a) || typed_recipes(b, &info_b)))
		goto out;
	puts("RUNTIME_REMOVE_FIRST");
	if (wait_mask(control, 2) < 0 || stale_adapter(a) < 0 ||
	    same_adapter(b, &info_b) < 0 || query_mac(b, &info_b) < 0)
		goto out;
	puts("RUNTIME_READD_FIRST");
	if (wait_mask(control, 3) < 0 || stale_adapter(a) < 0 ||
	    same_adapter(b, &info_b) < 0)
		goto out;
	replacement = bind_adapter(0, &info_new);
	if (replacement < 0 || query_mac(replacement, &info_new) < 0 ||
	    query_mac(b, &info_b) < 0 || stale_adapter(a) < 0)
		goto out;
	puts("RUNTIME_LIFECYCLE: PASS");
out:
	if (control < 0)
		fail("control open");
	if (replacement >= 0)
		close(replacement);
	if (b >= 0)
		close(b);
	if (a >= 0)
		close(a);
	if (control >= 0)
		close(control);
	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
