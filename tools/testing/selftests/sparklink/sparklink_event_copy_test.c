// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
/* Passive live read(2) usercopy gate. The supervisor produces real events
 * through slctl/D-Bus and acknowledges each case; no kernel injection hook.
 * VM-only qualification is enforced by the enclosing lab runner.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"

#define RECORD sizeof(struct sle_wire_event)
#define MAX_RECORDS 64
_Static_assert(RECORD == 44, "fixed legacy record size");

static void require(int ok, const char *message)
{
	if (!ok) {
		fprintf(stderr, "EVENT_COPY_FAILURE: %s (errno=%d)\n", message, errno);
		exit(EXIT_FAILURE);
	}
}

static struct sle_event_stats stats(int fd)
{
	struct sle_event_stats s = { 0 };

	require(ioctl(fd, SL_IOCTL_EVENT_STATS, &s) == 0, "event stats");
	return s;
}

static void print_stats(const struct sle_event_stats *s)
{
	printf("{\"pending\":%u,\"enqueued\":%llu,\"dropped\":%llu,\"delivered\":%llu}",
	       s->pending, (unsigned long long)s->total_enqueued,
	       (unsigned long long)s->total_dropped, (unsigned long long)s->total_delivered);
}

static void print_hex(const unsigned char *data, size_t size)
{
	putchar('"');
	for (size_t i = 0; i < size; i++)
		printf("%02x", data[i]);
	putchar('"');
}

static int open_bound(int16_t id)
{
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	struct sci_dev_info info = { 0 };

	require(fd >= 0, "open");
	require(ioctl(fd, SL_IOCTL_DEV_SELECT, &id) == 0, "per-fd binding");
	require(ioctl(fd, SL_IOCTL_DEV_INFO, &info) == 0 && info.index == id, "selected identity");
	return fd;
}

int main(int argc, char **argv)
{
	const char *names[] = { "zero", "short", "bad_address", "partial_first",
		"partial_later", "capacity_tail", "complete_batch" };
	char *end;
	long index, page = sysconf(_SC_PAGESIZE);

	require(argc == 2 && getuid() != 0 && getuid() == geteuid(), "ordinary uid and index required");
	index = strtol(argv[1], &end, 10);
	require(*argv[1] && !*end && index >= 0 && index < 16 && page > (long)(3 * RECORD), "index/page range");
	for (unsigned int test = 0; test < sizeof(names) / sizeof(names[0]); test++) {
		int fd = open_bound(index), reference_fd = open_bound(index);
		struct pollfd pollers[2] = { { .fd = fd, .events = POLLIN },
			{ .fd = reference_fd, .events = POLLIN } };
		struct sle_event_stats before, reference_before, after, final;
		unsigned char reference[MAX_RECORDS * RECORD], copied[MAX_RECORDS * RECORD];
		unsigned char *mapping = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), *destination;
		char acknowledgment[32];
		size_t length, committed = 0, partial_prefix = 0;
		ssize_t result, remaining;
		int error;

		require(mapping != MAP_FAILED, "mmap");
		printf("{\"ready\":\"%s\",\"uid\":%u}\n", names[test], getuid());
		fflush(stdout);
		require(fgets(acknowledgment, sizeof(acknowledgment), stdin) &&
			!strcmp(acknowledgment, "events-ready\n"), "producer acknowledgment");
		require(poll(pollers, 2, 0) == 2 &&
			pollers[0].revents == POLLIN && pollers[1].revents == POLLIN, "independent queue readiness");
		before = stats(fd); reference_before = stats(reference_fd);
		require(before.pending >= 2 && before.pending <= MAX_RECORDS &&
			!before.total_dropped && !before.total_delivered &&
			before.pending == reference_before.pending &&
			before.total_enqueued == reference_before.total_enqueued, "quiet shared event baseline");
		length = before.pending * RECORD;
		require(read(reference_fd, reference, sizeof(reference)) == (ssize_t)length, "reference complete records");
		require(stats(fd).pending == before.pending, "reference does not consume tested fd");
		memset(mapping, 0xa5, 2 * page);
		require(mprotect(mapping + page, page, PROT_NONE) == 0, "guard page");
		destination = mapping;
		errno = 0;
		switch (test) {
		case 0: result = read(fd, NULL, 0); break;
		case 1: result = read(fd, destination, RECORD - 1); break;
		case 2: result = read(fd, mapping + page, RECORD); break;
		case 3:
			destination = mapping + page - RECORD / 2;
			result = read(fd, destination, RECORD);
			break;
		case 4:
			destination = mapping + page - RECORD - RECORD / 2;
			result = read(fd, destination, 2 * RECORD);
			committed = RECORD;
			break;
		case 5:
			result = read(fd, destination, 2 * RECORD - 1);
			committed = RECORD;
			break;
		default:
			result = read(fd, destination, length);
			committed = length;
		}
		error = errno;
		require((test == 1 && result == -1 && error == EINVAL) ||
			((test == 2 || test == 3) && result == -1 && error == EFAULT) ||
			((test == 0 || test >= 4) && result == (ssize_t)committed), "whole-record result/errno");
		if (committed)
			require(!memcmp(destination, reference, committed), "complete prefix bytes");
		if (test == 3 || test == 4) {
			while (partial_prefix < RECORD / 2 && destination[committed + partial_prefix] == reference[committed + partial_prefix])
				partial_prefix++;
			require(partial_prefix > 0, "actual partial usercopy must be observed");
		}
		after = stats(fd);
		require(after.pending == before.pending - committed / RECORD &&
			after.total_delivered == committed / RECORD &&
			after.total_enqueued == before.total_enqueued && !after.total_dropped, "copy commit accounting");
		require(mprotect(mapping + page, page, PROT_READ | PROT_WRITE) == 0, "restore guard");
		if (length != committed) {
			remaining = read(fd, copied, sizeof(copied));
			require(remaining == (ssize_t)(length - committed) &&
				!memcmp(copied, reference + committed, remaining), "retained records exact retry");
		}
		final = stats(fd);
		require(!final.pending && final.total_delivered == before.pending && !final.total_dropped, "final delivery accounting");
		errno = 0;
		require(read(fd, copied, RECORD) == -1 && errno == EAGAIN, "empty read is not EOF");
		printf("{\"case\":\"%s\",\"result\":%zd,\"errno\":%d,\"partial_prefix\":%zu,\"before\":",
		       names[test], result, error, partial_prefix);
		print_stats(&before); printf(",\"after\":"); print_stats(&after);
		printf(",\"final\":"); print_stats(&final);
		printf(",\"reference\":"); print_hex(reference, length);
		printf(",\"retry\":");
		print_hex(length == committed ? reference : copied, length - committed);
		printf("}\n"); fflush(stdout);
		require(munmap(mapping, 2 * page) == 0, "munmap");
		close(reference_fd); close(fd);
	}
	return EXIT_SUCCESS;
}
