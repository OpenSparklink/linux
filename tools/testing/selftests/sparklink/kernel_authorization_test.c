// SPDX-License-Identifier: GPL-2.0-only
/* Actual syscall authorization against a native synthetic USB Runtime.
 * No physical firmware/RF evidence. Open-fd inheritance is deliberately tested.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
#include "../../../../include/uapi/linux/sparklink.h"
#include "retired_ioctl_cases.h"

static const unsigned long protected[] = {
    SL_IOCTL_SNOOP_GET,
    SL_IOCTL_DIAGNOSTIC_RESULT,
    SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT,
    SL_IOCTL_SECURITY_NEGOTIATION_RESULT,
    SL_IOCTL_SECURITY_NEGOTIATION_CANCEL,
    SL_IOCTL_SECURITY_NUMERIC_CONFIRM,
    SL_IOCTL_CONNECTION_SECURITY,
    SL_IOCTL_DIAGNOSTIC_SUBMIT,
    SL_IOCTL_MANAGEMENT_ACQUIRE,
    SL_IOCTL_MANAGEMENT_RELEASE,
    SL_IOCTL_CONNECTION_SUBMIT,
    SL_IOCTL_DISCOVERY_SUBMIT,
};
static const unsigned long observe[] = {
    SL_IOCTL_MANAGEMENT_QUERY,
    SL_IOCTL_CONTROLLER_EVENT_GET,
    SL_IOCTL_CONTROLLER_SNAPSHOT,
    SL_IOCTL_REGISTRATION_SNAPSHOT,
    SL_IOCTL_DEV_COUNT,
    SL_IOCTL_DEV_INFO,
    SL_IOCTL_DEV_LIST,
    SL_IOCTL_CONNECTION_RESULT,
    SL_IOCTL_LINK_SNAPSHOT,
    SL_IOCTL_DISCOVERY_RESULT,
    SL_IOCTL_DISCOVERY_TIMING,
    SL_IOCTL_MGMT_STATS,
};
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))
static const char *attrs[] = { "max_connections", "adv_interval_ms", "scan_window_ms", "power_mode", "controller_type" };

static int failure(const char *reason)
{
	fprintf(stderr, "KERNEL_AUTH_FAILURE: %s errno=%d\n", reason, errno);
	return 1;
}

static int genl_request(int fd, unsigned short family, unsigned char cmd,
			const void *payload, unsigned length, unsigned sequence,
			unsigned char *reply, unsigned capacity)
{
	unsigned char buffer[256] = { 0 };
	struct nlmsghdr *header = (void *)buffer;
	struct genlmsghdr *generic = (void *)(buffer + NLMSG_HDRLEN);
	struct sockaddr_nl target = { .nl_family = AF_NETLINK };
	header->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN + length;
	header->nlmsg_type = family;
	header->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	header->nlmsg_seq = sequence;
	generic->cmd = cmd;
	generic->version = family == GENL_ID_CTRL ? 1 : SPARKLINK_GENL_VERSION;
	if (length) memcpy(buffer + NLMSG_HDRLEN + GENL_HDRLEN, payload, length);
	if (sendto(fd, buffer, header->nlmsg_len, 0, (void *)&target, sizeof(target)) < 0)
		return -errno;
	for (;;) {
		int count = recv(fd, reply, capacity, 0);
		if (count < 0) return -errno;
		if (!count) return -EPROTO;
		unsigned remaining = (unsigned)count;
		for (struct nlmsghdr *h = (void *)reply; NLMSG_OK(h, remaining); h = NLMSG_NEXT(h, remaining)) {
			if (h->nlmsg_seq != sequence) continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return -EPROTO;
				return ((struct nlmsgerr *)NLMSG_DATA(h))->error;
			}
			if (h->nlmsg_type == family) return h->nlmsg_len;
		}
	}
}

static int genl_denied(void)
{
	unsigned char attr[64] = { 0 }, reply[512];
	struct nlattr *name = (void *)attr;
	struct timeval timeout = { .tv_sec = 2 };
	unsigned short family = 0;
	int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
		return failure("ordinary netlink socket");
	name->nla_type = CTRL_ATTR_FAMILY_NAME;
	name->nla_len = NLA_HDRLEN + sizeof("sparklink");
	memcpy(attr + NLA_HDRLEN, "sparklink", sizeof("sparklink"));
	int result = genl_request(fd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attr, NLA_ALIGN(name->nla_len), 1, reply, sizeof(reply));
	if (result <= (int)(NLMSG_HDRLEN + GENL_HDRLEN)) return failure("resolve public netlink family");
	for (unsigned offset = NLMSG_HDRLEN + GENL_HDRLEN; offset + NLA_HDRLEN <= (unsigned)result;) {
		struct nlattr *a = (void *)(reply + offset);
		if (a->nla_len < NLA_HDRLEN || offset + a->nla_len > (unsigned)result) return failure("malformed family reply");
		if (a->nla_type == CTRL_ATTR_FAMILY_ID && a->nla_len == NLA_HDRLEN + sizeof(family))
			memcpy(&family, reply + offset + NLA_HDRLEN, sizeof(family));
		offset += NLA_ALIGN(a->nla_len);
	}
	if (!family) return failure("missing public family id");
	/* Historical command numbers; not current production declarations. */
	unsigned char commands[] = { 29, 4, 5, 6, 7 };
	for (unsigned i = 0; i < COUNT(commands); ++i)
		if (genl_request(fd, family, commands[i], NULL, 0, i + 2, reply, sizeof(reply)) != -EOPNOTSUPP)
			return failure("retired netlink mutation must be unsupported");
	close(fd);
	return 0;
}

static int child(int fd, uid_t uid, gid_t gid, int id, __u64 generation)
{
	struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct caps[2] = { 0 };
	gid_t groups[1] = { 1000 };
	int selected = id;
	if (setgroups(uid == 1000 ? 1 : 0, groups) || setresgid(gid, gid, gid) || setresuid(uid, uid, uid) ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) || syscall(SYS_capset, &header, caps) ||
	    syscall(SYS_capget, &header, caps))
		return failure("drop credentials/capabilities");
	for (unsigned i = 0; i < 2; ++i)
		if (caps[i].effective || caps[i].permitted || caps[i].inheritable)
			return failure("nonzero application capability");
	for (unsigned i = 0; i <= CAP_LAST_CAP; ++i)
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0) != 0)
			return failure("ambient capability");
	if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid)
		return failure("unexpected credentials");
	/* These are real inherited fds, not a DAC-only failed open. */
	for (unsigned i = 0; i < COUNT(protected); ++i) {
		errno = 0;
		if (ioctl(fd, protected[i], NULL) != -1 || errno != EPERM) {
			fprintf(stderr, "protected ioctl=0x%lx uid=%u\n", protected[i], uid);
			return failure("protected call not rejected before userspace memory");
		}
	}
	for (unsigned i = 0; i < COUNT(observe); ++i) {
		errno = 0;
		ioctl(fd, observe[i], NULL);
		if (errno == EPERM || errno == ENOTTY)
			return failure("observation denied or unclassified");
	}
	__s16 affinity = selected;
	__u16 active;
	struct sle_controller_snapshot snapshot = { .version = 1, .generation = generation };
	if (ioctl(fd, SL_IOCTL_DEV_SELECT, &affinity) || ioctl(fd, SL_IOCTL_DEV_GET_ACTIVE, &active) || active != id ||
	    ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &snapshot) || snapshot.generation != generation || snapshot.flags != 1)
		return failure("ordinary affinity/Ready observation");
	errno = 0;
	if (ioctl(fd, _IO('S', 0xff), NULL) != -1 || errno != ENOTTY)
		return failure("unknown ABI command must be ENOTTY");
	/* Removed no-op C and historical Rust write_int encodings are unknown,
	 * before capability, selection or user-memory access. */
	const unsigned long retired[] = { 0x00005301, 0x40025302, 0x40045302 };
	for (unsigned i = 0; i < COUNT(retired); ++i) {
		errno = 0;
		if (ioctl(fd, retired[i], (void *)1) != -1 || errno != ENOTTY)
			return failure("retired registration ABI must be ENOTTY");
	}
	for (unsigned i = 0; i < COUNT(sl_test_retired_commands); ++i) {
		errno = 0;
		if (ioctl(fd, sl_test_retired_commands[i], (void *)1) != -1 || errno != ENOTTY)
			return failure("retired ioctl must reject before capability/usercopy");
	}
	for (unsigned i = 0; i < COUNT(attrs); ++i) {
		char path[128]; struct stat st;
		snprintf(path, sizeof(path), "/sys/kernel/config/sparklink/%s", attrs[i]);
		if (lstat(path, &st) != -1 || errno != ENOENT)
			return failure("retired configfs mutation reappeared");
	}
	if (genl_denied()) return 1;
	printf("KERNEL_AUTHORIZATION: uid=%u gid=%u caps=0 inherited_fd=1 protected=%zu denied=%zu observe=%zu retired_enotty=101 configfs_absent=5 genl_denied=5 unknown=ENOTTY\n",
	       uid, gid, COUNT(protected), COUNT(protected), COUNT(observe));
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned id; unsigned long long gen;
	int status;
	if (argc != 2 || sscanf(argv[1], "/org/sparklink/slk%u_g%llu", &id, &gen) != 2 || id > 15 || !gen || getuid())
		return failure("root fixture needs selected path");
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) && errno != EBUSY)
		return failure("mount configfs");
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	__s16 selected = id;
	struct sle_controller_snapshot before = { .version = 1, .generation = gen }, after;
	struct sle_mgmt_stats stats_before, stats_after;
	__u16 mask_before, mask_after;
	if (fd < 0 || ioctl(fd, SL_IOCTL_DEV_SELECT, &selected) || ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &before) ||
	    before.flags != 1 || ioctl(fd, SL_IOCTL_MGMT_STATS, &stats_before) || ioctl(fd, SL_IOCTL_DEV_LIST, &mask_before))
		return failure("baseline Ready/management state");
	uid_t uids[] = { 1001, 1000, 0 }; gid_t gids[] = { 1001, 1002, 0 };
	for (unsigned i = 0; i < COUNT(uids); ++i) {
		pid_t pid = fork();
		if (pid < 0) return failure("fork fixture");
		if (!pid) _exit(child(fd, uids[i], gids[i], id, gen));
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
			return failure("child permission matrix failed");
	}
	after = (struct sle_controller_snapshot){ .version = 1, .generation = gen };
	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &after) || memcmp(&before, &after, sizeof(before)) ||
	    ioctl(fd, SL_IOCTL_MGMT_STATS, &stats_after) || memcmp(&stats_before, &stats_after, sizeof(stats_before)) ||
	    ioctl(fd, SL_IOCTL_DEV_LIST, &mask_after) || mask_before != mask_after)
		return failure("denied calls changed registration, snapshot or command admission");
	close(fd);
	puts("KERNEL_AUTHORIZATION_STATE: unchanged=1 native_admission=0 retired_mutations_absent=1");
	return 0;
}
