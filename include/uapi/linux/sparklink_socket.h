/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SPARKLINK_SOCKET_H
#define _UAPI_LINUX_SPARKLINK_SOCKET_H
#include <linux/types.h>

/* Experimental/unpublished. Broker binds with CAP_NET_ADMIN and can pass the
 * SOCK_DGRAM fd to ordinary applications. Basic mode has no reliable delivery
 * promise. SOCK_SEQPACKET requires a qualified reliable mode and is rejected.
 * No mutation/raw DLI permission.
 */
struct sockaddr_sparklink {
	__u16 family, controller;
	__u16 version, flags;
	__u64 generation, lifetime;
	__u16 handle;
	__u8 local_tcid, remote_tcid, pi, reserved[3];
};
#define SPARKLINK_SOCKET_VERSION 1
#define SPARKLINK_SOCKET_USER_PI 241
#endif
