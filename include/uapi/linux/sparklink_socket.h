/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SPARKLINK_SOCKET_H
#define _UAPI_LINUX_SPARKLINK_SOCKET_H
#include <linux/types.h>

/* Experimental/unpublished. Broker binds with CAP_NET_ADMIN and can pass the
 * SOCK_DGRAM fd to ordinary applications. Basic mode has no reliable delivery
 * promise. SOCK_SEQPACKET requires a qualified reliable mode and is rejected.
 * lease is the current Managed token; release/owner death invalidates it.
 * A successor lease never renews the old fd. Kernel enforces admission and
 * actual USB submission; accepted physical obligations are retained.
 * directions is TX, RX, or TX|RX. Forbidden send/recv returns EACCES;
 * poll advertises only granted readiness. CMTC belongs to Session.
 * Current basic mode only accepts security=NONE; protected requests reject.
 * No mutation/raw DLI permission.
 */
struct sockaddr_sparklink {
	__u16 family, controller;
	__u16 version, flags;
	__u64 generation, lifetime, lease;
	__u16 handle;
	__u8 local_tcid, remote_tcid, pi, reserved[3];
	__u32 directions, security;
};
#define SPARKLINK_SOCKET_VERSION 2
#define SPARKLINK_SOCKET_TX 1
#define SPARKLINK_SOCKET_RX 2
#define SPARKLINK_SOCKET_SECURITY_NONE 0
#define SPARKLINK_SOCKET_SECURITY_ENCRYPTED 1
#define SPARKLINK_SOCKET_SECURITY_AUTHENTICATED 2
/* Protected security requirements are defined but currently unsupported. */
#define SPARKLINK_SOCKET_USER_PI 241
#endif
