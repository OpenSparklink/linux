// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE
/* Passive ordinary-user current ControllerEvent VFS probe. No command or injection. */
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
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"CONTROLLER_COPY_FAIL line=%u errno=%d\n",__LINE__,errno); exit(1); } } while (0)

static int selected(uint16_t id)
{
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	CHECK(fd >= 0 && !ioctl(fd, SL_IOCTL_DEV_SELECT, &id));
	return fd;
}

static struct sle_controller_event_query input(int fd, uint64_t generation)
{
	struct sle_link_snapshot s = { .version = 1, .generation = generation };
	CHECK(!ioctl(fd, SL_IOCTL_LINK_SNAPSHOT, &s) && s.event_seq);
	return (struct sle_controller_event_query){ .version = 1,
		.generation = generation, .after_seq = s.event_seq - 1 };
}

int main(int argc, char **argv)
{
	CHECK(argc == 3 && getuid() == 1000 && geteuid() == 1000);
	uint16_t id = strtoul(argv[1], NULL, 10);
	uint64_t generation = strtoull(argv[2], NULL, 10);
	CHECK(id < 16 && generation);
	int a = selected(id), b = selected(id);
	const size_t prefixes[] = { 32, 48, 96, 240 };
	long page = sysconf(_SC_PAGESIZE);
	CHECK(page > (long)sizeof(struct sle_controller_event_query));
	for (unsigned n = 0; n < sizeof(prefixes)/sizeof(prefixes[0]); n++) {
		struct sle_controller_event_query q = input(b, generation), reference = q;
		CHECK(!ioctl(b, SL_IOCTL_CONTROLLER_EVENT_GET, &reference));
		CHECK(reference.event.seq == q.after_seq + 1 && reference.event.generation == generation);
		unsigned char *map = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		CHECK(map != MAP_FAILED);
		unsigned char *destination = map + page - prefixes[n];
		memcpy(destination, &q, sizeof(q));
		CHECK(!mprotect(map + page, page, PROT_READ));
		errno = 0;
		CHECK(ioctl(a, SL_IOCTL_CONTROLLER_EVENT_GET, destination) == -1 && errno == EFAULT);
		CHECK(!memcmp(destination, &reference, prefixes[n]) && memcmp(destination, &q, prefixes[n]));
		struct pollfd p = { .fd = a, .events = POLLIN };
		CHECK(poll(&p, 1, 0) == 1 && p.revents & POLLIN && !(p.revents & (POLLERR | POLLHUP)));
		struct sle_controller_event_query retry = q, replay = q;
		CHECK(!ioctl(a, SL_IOCTL_CONTROLLER_EVENT_GET, &retry) && !memcmp(&retry, &reference, sizeof(retry)));
		CHECK(!ioctl(b, SL_IOCTL_CONTROLLER_EVENT_GET, &replay) && !memcmp(&replay, &reference, sizeof(replay)));
		CHECK(!munmap(map, 2 * page));
	}
	unsigned char removed[64]; memset(removed, 0xa5, sizeof(removed));
	errno = 0; CHECK(read(a, removed, sizeof(removed)) == -1 && errno == EOPNOTSUPP);
	for (unsigned n = 0; n < sizeof(removed); n++) CHECK(removed[n] == 0xa5);
	CHECK(ioctl(a, 0x5370U, NULL) == -1 && errno == ENOTTY);
	CHECK(ioctl(a, 0x80205371U, removed) == -1 && errno == ENOTTY);
	for (unsigned n = 0; n < sizeof(removed); n++) CHECK(removed[n] == 0xa5);
	CHECK(!close(a) && !close(b));
	printf("CONTROLLER_EVENT_COPY_PASS: uid=1000 index=%u generation=%llu partial=4 retry=4 peer_replay=4 readiness_preserved=4 removed_read=1 removed_stats=2\n",id,(unsigned long long)generation);
	return 0;
}
