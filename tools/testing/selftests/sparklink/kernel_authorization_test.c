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
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
#include "../../../../include/uapi/linux/sparklink.h"

static const unsigned long protected[] = {
	SL_IOCTL_AFH_CLASSIFY,
	SL_IOCTL_AFH_HOP_NEXT,
	SL_IOCTL_AFH_REPORT_RETX,
	SL_IOCTL_AFH_REPORT_RSSI,
	SL_IOCTL_AFH_SET_MAP,
	SL_IOCTL_CLEAR_SCAN_FILTER,
	SL_IOCTL_CONNECT,
	SL_IOCTL_CONN_PHY_UPDATE,
	SL_IOCTL_CONN_READ_PEER_FEATURES,
	SL_IOCTL_CONN_READ_PEER_VERSION,
	SL_IOCTL_CONN_RECV,
	SL_IOCTL_CONN_SEND,
	SL_IOCTL_CONN_UPDATE_PARAMS,
	SL_IOCTL_DEV_REGISTER,
	SL_IOCTL_DEV_SWITCH,
	SL_IOCTL_DEV_UNREGISTER,
	SL_IOCTL_DISCONNECT,
	SL_IOCTL_DISCOVERY_SUBMIT,
	SL_IOCTL_DLI_POLL_EVENT,
	SL_IOCTL_DLI_RESET,
	SL_IOCTL_DLI_SEND_CMD,
	SL_IOCTL_EXT_ADV_CONFIGURE,
	SL_IOCTL_EXT_ADV_DISABLE,
	SL_IOCTL_EXT_ADV_ENABLE,
	SL_IOCTL_EXT_ADV_ENABLE_EX,
	SL_IOCTL_EXT_ADV_REMOVE,
	SL_IOCTL_EXT_ADV_SET_DATA,
	SL_IOCTL_EXT_ADV_SET_SCAN_RSP,
	SL_IOCTL_EXT_ADV_TICK,
	SL_IOCTL_INJECT_ADV,
	SL_IOCTL_INJECT_CONN_DATA,
	SL_IOCTL_INJECT_CONN_RESP,
	SL_IOCTL_INJECT_RAW_ADV,
	SL_IOCTL_MEAS_ACTION,
	SL_IOCTL_MEAS_ENABLE,
	SL_IOCTL_MEAS_SET_LINK_PARAM,
	SL_IOCTL_PHY_HOP_NEXT,
	SL_IOCTL_PHY_MCS_SELECT,
	SL_IOCTL_PHY_SET_BW,
	SL_IOCTL_PHY_SET_MCS,
	SL_IOCTL_PHY_SET_SINR,
	SL_IOCTL_PHY_SET_TXPOWER,
	SL_IOCTL_PM_ACTIVITY,
	SL_IOCTL_PM_FORCE_ACTIVE,
	SL_IOCTL_PM_SET_INTERVAL,
	SL_IOCTL_PM_SET_STATE,
	SL_IOCTL_PM_TICK,
	SL_IOCTL_RAL_ADD,
	SL_IOCTL_RAL_CLEAR,
	SL_IOCTL_RAL_READ_LOCAL_RPA,
	SL_IOCTL_RAL_READ_PEER_RPA,
	SL_IOCTL_RAL_REMOVE,
	SL_IOCTL_RPA_ENABLE,
	SL_IOCTL_RPA_SET_TIMEOUT,
	SL_IOCTL_SEC_CONFIRM_PASSKEY,
	SL_IOCTL_SEC_ENCRYPT_ON,
	SL_IOCTL_SEC_GET_PASSKEY,
	SL_IOCTL_SEC_INPUT_PASSKEY,
	SL_IOCTL_SEC_PAIR,
	SL_IOCTL_SEC_REJECT_PASSKEY,
	SL_IOCTL_SEC_RESET,
	SL_IOCTL_SEC_SET_OOB,
	SL_IOCTL_SEC_SET_PASSWORD,
	SL_IOCTL_SEC_SET_PSK,
	SL_IOCTL_SET_CONN_MTU,
	SL_IOCTL_SET_ROLE,
	SL_IOCTL_SET_SCAN_FILTER,
	SL_IOCTL_SSAP_ADD_PROP,
	SL_IOCTL_SSAP_ADD_SVC,
	SL_IOCTL_SSAP_CALL_METHOD,
	SL_IOCTL_SSAP_DEQUEUE_NTF,
	SL_IOCTL_SSAP_EXCHANGE_INFO,
	SL_IOCTL_SSAP_FIND_BY_UUID,
	SL_IOCTL_SSAP_NOTIFY,
	SL_IOCTL_SSAP_READ_BY_UUID,
	SL_IOCTL_SSAP_REGISTER_SVC,
	SL_IOCTL_SSAP_REMOTE_DISCOVER,
	SL_IOCTL_SSAP_REMOTE_EVENT,
	SL_IOCTL_SSAP_REMOTE_READ,
	SL_IOCTL_SSAP_REMOTE_WRITE,
	SL_IOCTL_SSAP_REMOVE_SVC,
	SL_IOCTL_SSAP_WRITE,
	SL_IOCTL_START_ADV,
	SL_IOCTL_START_SCAN,
	SL_IOCTL_STOP_ADV,
	SL_IOCTL_STOP_SCAN,
	SL_IOCTL_SYNC_DATAPATH_CFG,
	SL_IOCTL_SYNC_DATAPATH_REMOVE,
	SL_IOCTL_SYNC_DATA_SEND,
	SL_IOCTL_SYNC_MCAST_ACCEPT,
	SL_IOCTL_SYNC_MCAST_CREATE,
	SL_IOCTL_SYNC_MCAST_PARAM,
	SL_IOCTL_SYNC_MCAST_REJECT,
	SL_IOCTL_SYNC_MCAST_REMOVE,
	SL_IOCTL_SYNC_UCAST_ACCEPT,
	SL_IOCTL_SYNC_UCAST_CREATE,
	SL_IOCTL_SYNC_UCAST_PARAM,
	SL_IOCTL_SYNC_UCAST_REJECT,
	SL_IOCTL_SYNC_UCAST_REMOVE,
};
static const unsigned long observe[] = {
	SL_IOCTL_AFH_GET_MAP,
	SL_IOCTL_CONN_COUNT,
	SL_IOCTL_CONN_INFO,
	SL_IOCTL_CONN_LIST,
	SL_IOCTL_CONTROLLER_EVENT_GET,
	SL_IOCTL_CONTROLLER_SNAPSHOT,
	SL_IOCTL_DEV_COUNT,
	SL_IOCTL_DEV_INFO,
	SL_IOCTL_DEV_LIST,
	SL_IOCTL_DISCOVERY_RESULT,
	SL_IOCTL_DLI_INFO,
	SL_IOCTL_EVENT_COUNT,
	SL_IOCTL_EVENT_STATS,
	SL_IOCTL_EXT_ADV_INFO,
	SL_IOCTL_GET_ROLE,
	SL_IOCTL_MEAS_READ_CAP,
	SL_IOCTL_MGMT_STATS,
	SL_IOCTL_PHY_GET_SINR,
	SL_IOCTL_PHY_INFO,
	SL_IOCTL_PM_INFO,
	SL_IOCTL_RAL_SIZE,
	SL_IOCTL_SCAN_RESULT_COUNT,
	SL_IOCTL_SEC_HMAC_TEST,
	SL_IOCTL_SEC_INFO,
	SL_IOCTL_SEC_SM3_TEST,
	SL_IOCTL_SEC_SM4_BLOCK_TEST,
	SL_IOCTL_SEC_SM4_DEC_TEST,
	SL_IOCTL_SEC_SM4_ENC_TEST,
	SL_IOCTL_SSAP_FIND_SVC,
	SL_IOCTL_SSAP_INFO,
	SL_IOCTL_SSAP_READ,
	SL_IOCTL_SUBSYS_STATS,
	SL_IOCTL_SYNC_INFO,
	SL_IOCTL_USB_DEV_COUNT,
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
	generic->version = 1;
	if (length) memcpy(buffer + NLMSG_HDRLEN + GENL_HDRLEN, payload, length);
	if (sendto(fd, buffer, header->nlmsg_len, 0, (void *)&target, sizeof(target)) < 0)
		return -errno;
	for (;;) {
		int count = recv(fd, reply, capacity, 0);
		if (count < 0) return -errno;
		for (struct nlmsghdr *h = (void *)reply; NLMSG_OK(h, count); h = NLMSG_NEXT(h, count)) {
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
	unsigned char commands[] = { SPARKLINK_CMD_SET_ROLE, SPARKLINK_CMD_START_ADV, SPARKLINK_CMD_STOP_ADV,
				     SPARKLINK_CMD_START_SCAN, SPARKLINK_CMD_STOP_SCAN };
	for (unsigned i = 0; i < COUNT(commands); ++i)
		if (genl_request(fd, family, commands[i], NULL, 0, i + 2, reply, sizeof(reply)) != -EPERM)
			return failure("netlink managed mutation without capability");
	close(fd);
	return 0;
}

static int child(int fd, int config[5], uid_t uid, gid_t gid, int id, __u64 generation)
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
	for (unsigned i = 0; i < COUNT(attrs); ++i) {
		errno = 0;
		if (write(config[i], "0", 1) != -1 || errno != EPERM)
			return failure("inherited configfs store bypassed authorization");
	}
	if (genl_denied()) return 1;
	printf("KERNEL_AUTHORIZATION: uid=%u gid=%u caps=0 inherited_fd=1 protected=%zu denied=%zu observe=%zu configfs_denied=5 genl_denied=5 unknown=ENOTTY\n",
	       uid, gid, COUNT(protected), COUNT(protected), COUNT(observe));
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned id; unsigned long long gen;
	int config[5], status;
	if (argc != 2 || sscanf(argv[1], "/org/sparklink/slk%u_g%llu", &id, &gen) != 2 || id > 15 || !gen || getuid())
		return failure("root fixture needs selected path");
	if (mount("none", "/sys/kernel/config", "configfs", 0, NULL) && errno != EBUSY)
		return failure("mount configfs");
	for (unsigned i = 0; i < COUNT(attrs); ++i) {
		char path[128];
		snprintf(path, sizeof(path), "/sys/kernel/config/sparklink/%s", attrs[i]);
		config[i] = open(path, O_WRONLY);
		if (config[i] < 0) return failure("root opens configfs fixture");
	}
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	__s16 selected = id;
	struct sle_controller_snapshot before = { .version = 1, .generation = gen }, after;
	struct sle_mgmt_stats stats_before, stats_after;
	struct sle_pm_info pm_before, pm_after;
	__u16 mask_before, mask_after;
	if (fd < 0 || ioctl(fd, SL_IOCTL_DEV_SELECT, &selected) || ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &before) ||
	    before.flags != 1 || ioctl(fd, SL_IOCTL_MGMT_STATS, &stats_before) || ioctl(fd, SL_IOCTL_DEV_LIST, &mask_before))
		return failure("baseline Ready/management state");
	if (ioctl(fd, SL_IOCTL_PM_INFO, &pm_before) || write(config[3], "idle", 4) != 4)
		return failure("baseline power/pending configfs policy");
	uid_t uids[] = { 1001, 1000, 0 }; gid_t gids[] = { 1001, 1002, 0 };
	for (unsigned i = 0; i < COUNT(uids); ++i) {
		pid_t pid = fork();
		if (pid < 0) return failure("fork fixture");
		if (!pid) _exit(child(fd, config, uids[i], gids[i], id, gen));
		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
			return failure("child permission matrix failed");
	}
	after = (struct sle_controller_snapshot){ .version = 1, .generation = gen };
	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &after) || memcmp(&before, &after, sizeof(before)) ||
	    ioctl(fd, SL_IOCTL_MGMT_STATS, &stats_after) || memcmp(&stats_before, &stats_after, sizeof(stats_before)) ||
	    ioctl(fd, SL_IOCTL_DEV_LIST, &mask_after) || mask_before != mask_after ||
	    ioctl(fd, SL_IOCTL_PM_INFO, &pm_after) || memcmp(&pm_before, &pm_after, sizeof(pm_before)))
		return failure("denied calls changed registration, snapshot or command admission");
	if (lseek(config[3], 0, SEEK_SET) < 0 || write(config[3], "active", 6) != 6)
		return failure("restore fixture power policy");
	for (unsigned i = 0; i < COUNT(attrs); ++i) close(config[i]);
	close(fd);
	puts("KERNEL_AUTHORIZATION_STATE: unchanged=1 native_admission=0 observe_no_power_sync=1");
	return 0;
}
