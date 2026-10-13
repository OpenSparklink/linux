/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SPARKLINK_SOCKET_H
#define _UAPI_LINUX_SPARKLINK_SOCKET_H
#include <linux/types.h>
#include <linux/ioctl.h>

/* Experimental/unpublished. Broker binds with CAP_NET_ADMIN and can pass the
 * SOCK_DGRAM fd to ordinary applications. Basic mode has no reliable delivery
 * promise. SOCK_SEQPACKET requires a qualified reliable mode and is rejected.
 * lease is the current Managed token; release/owner death invalidates it.
 * A successor lease never renews the old fd. Kernel enforces admission and
 * actual USB submission; accepted physical obligations are retained.
 * directions is TX, RX, or TX|RX. Forbidden send/recv returns EACCES;
 * poll advertises only granted readiness. CMTC belongs to Session.
 * Current basic mode only accepts security=NONE; protected requests reject.
 * Fixed basic channels: CUTC local/remote TCID31 with USER_PI, or SLE SMTC
 * local/remote TCID10 with PI0. Each has one independent binding per physical
 * connection lifetime. Final close retires only that channel; same-lifetime
 * rebinding remains unsupported without a verified close/drain barrier.
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
/* Read-only delegated socket snapshot. No lease token or trusted security
 * projection. Success requires current Runtime authorization and completed
 * CMTC negotiation; EAGAIN before open, ENOTCONN after local close.
 * It is coherent at admission, not a promise of future connectivity.
 * Fixed 40-byte layout is identical for native and compat callers.
 */
struct sparklink_channel_info {
	__u16 version, size, controller, handle;
	__aligned_u64 generation, lifetime;
	__u16 mtu, mps;
	__u8 local_tcid, remote_tcid, pi, mode;
	__u32 directions, reserved;
};
#define SPARKLINK_CHANNEL_INFO_VERSION 1
#define SPARKLINK_CHANNEL_MODE_BASIC 0
#define SPARKLINK_CHANNEL_INFO _IOR('S', 0xe0, struct sparklink_channel_info)
#endif
