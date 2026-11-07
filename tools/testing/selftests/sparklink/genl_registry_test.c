// SPDX-License-Identifier: GPL-2.0-only
/* Passive guest-only test of the actual registry-only Generic Netlink family. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include "../../../../include/uapi/linux/sparklink.h"

static int registry_request(int fd, uint16_t family, uint8_t cmd,
                            const void *attrs, unsigned length, unsigned seq,
                            unsigned char *reply, unsigned capacity)
{
	unsigned char buffer[256] = {0};
	struct nlmsghdr *h = (void *)buffer;
	struct genlmsghdr *g = (void *)(buffer + NLMSG_HDRLEN);
	struct sockaddr_nl target = { .nl_family = AF_NETLINK };
	if (NLMSG_HDRLEN + GENL_HDRLEN + length > sizeof(buffer)) return -EMSGSIZE;
	h->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + length;
	h->nlmsg_type = family; h->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK; h->nlmsg_seq = seq;
	g->cmd = cmd; g->version = family == GENL_ID_CTRL ? 1 : SPARKLINK_GENL_VERSION;
	if (length) memcpy(buffer + NLMSG_HDRLEN + GENL_HDRLEN, attrs, length);
	if (sendto(fd, buffer, h->nlmsg_len, 0, (void *)&target, sizeof(target)) < 0) return -errno;
	for (;;) {
		int count = recv(fd, reply, capacity, 0);
		if (count <= 0) return count < 0 ? -errno : -EPROTO;
		unsigned remaining = count;
		for (h = (void *)reply; NLMSG_OK(h, remaining); h = NLMSG_NEXT(h, remaining)) {
			if (h->nlmsg_seq != seq) continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return -EPROTO;
				return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
			}
			if (h->nlmsg_type == family && h->nlmsg_len <= capacity) return h->nlmsg_len;
		}
	}
}

static const void *registry_attr(const unsigned char *reply, int length, unsigned type, unsigned size)
{
	for (unsigned off = NLMSG_HDRLEN + GENL_HDRLEN; off + NLA_HDRLEN <= (unsigned)length;) {
		const struct nlattr *a = (const void *)(reply + off);
		if (a->nla_len < NLA_HDRLEN || off + a->nla_len > (unsigned)length) return NULL;
		if ((a->nla_type & NLA_TYPE_MASK) == type)
			return !size || a->nla_len == NLA_HDRLEN + size ? reply + off + NLA_HDRLEN : NULL;
		off += NLA_ALIGN(a->nla_len);
	}
	return NULL;
}

static int registry_probe(int expected)
{
	unsigned char attrs[64] = {0}, reply[4096];
	struct nlattr *a = (void *)attrs;
	struct timeval timeout = { .tv_sec = 2 };
	uint16_t family; uint32_t count, version, protocol; const void *p;
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC), len;
#define REGISTRY_CHECK(x) do { if (!(x)) { fprintf(stderr, "GENL_REGISTRY_FAIL: line=%u errno=%d\n", __LINE__, errno); if (fd >= 0) close(fd); return 1; } } while (0)
	REGISTRY_CHECK(fd >= 0 && !setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
	a->nla_type = CTRL_ATTR_FAMILY_NAME; a->nla_len = NLA_HDRLEN + sizeof(SPARKLINK_GENL_NAME);
	memcpy(attrs + NLA_HDRLEN, SPARKLINK_GENL_NAME, sizeof(SPARKLINK_GENL_NAME));
	len = registry_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attrs, NLA_ALIGN(a->nla_len), 1, reply, sizeof(reply));
	REGISTRY_CHECK(len > 0 && (p = registry_attr(reply, len, CTRL_ATTR_FAMILY_ID, sizeof(family))));
	memcpy(&family, p, sizeof(family));
	REGISTRY_CHECK(!registry_attr(reply, len, CTRL_ATTR_MCAST_GROUPS, 0));
	len = registry_request(fd, family, SPARKLINK_CMD_GET_REGISTRY_COUNT, NULL, 0, 2, reply, sizeof(reply));
	REGISTRY_CHECK(len > 0 && (p = registry_attr(reply, len, SPARKLINK_ATTR_DEV_COUNT, sizeof(count))));
	memcpy(&count, p, sizeof(count)); REGISTRY_CHECK(expected < 0 || count == (unsigned)expected);
	REGISTRY_CHECK(((struct genlmsghdr *)(reply + NLMSG_HDRLEN))->version == SPARKLINK_GENL_VERSION);
	len = registry_request(fd, family, SPARKLINK_CMD_GET_VERSION, NULL, 0, 3, reply, sizeof(reply));
	REGISTRY_CHECK(len > 0 && (p = registry_attr(reply, len, SPARKLINK_ATTR_GENL_VERSION, sizeof(version))));
	memcpy(&version, p, sizeof(version)); REGISTRY_CHECK(version == SPARKLINK_GENL_VERSION);
	REGISTRY_CHECK((p = registry_attr(reply, len, SPARKLINK_ATTR_PROTO_VERSION, sizeof(protocol))));
	memcpy(&protocol, p, sizeof(protocol)); REGISTRY_CHECK(protocol == 0x000300);
	for (unsigned cmd = 2; cmd <= 33; cmd++) {
		if (cmd == SPARKLINK_CMD_GET_VERSION) continue;
		REGISTRY_CHECK(registry_request(fd, family, cmd, NULL, 0, cmd + 10, reply, sizeof(reply)) == -EOPNOTSUPP);
	}
	/* Requests are attribute-free; do not silently accept a removed DEV_INDEX. */
	a->nla_type = 1; a->nla_len = NLA_HDRLEN + 2;
	REGISTRY_CHECK(registry_request(fd, family, SPARKLINK_CMD_GET_REGISTRY_COUNT,
	                               attrs, NLA_ALIGN(a->nla_len), 100, reply, sizeof(reply)) == -EINVAL);
	len = registry_request(fd, family, SPARKLINK_CMD_GET_REGISTRY_COUNT, NULL, 0, 101, reply, sizeof(reply));
	REGISTRY_CHECK(len > 0 && (p = registry_attr(reply, len, SPARKLINK_ATTR_DEV_COUNT, sizeof(version))));
	memcpy(&version, p, sizeof(version)); REGISTRY_CHECK(version == count);
	close(fd);
	printf("GENL_REGISTRY_PASS: uid=%u count=%u version=2 retired=31 extra_attr=1 no_multicast=1 count_preserved=1\n", getuid(), count);
#undef REGISTRY_CHECK
	return 0;
}
#ifndef GENL_REGISTRY_EMBEDDED
int main(int argc, char **argv)
{
	int expected = -1;
	if (argc > 2) return 2;
	if (argc == 2) {
		char *end; long value = strtol(argv[1], &end, 10);
		if (*end || value < 0 || value > 65535) return 2;
		expected = value;
	}
	return registry_probe(expected);
}
#endif
