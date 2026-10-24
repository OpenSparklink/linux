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
 * Fixed channels accept NONE, ENCRYPTED or AUTHENTICATED below. Kernel
 * mints a frozen per-lifetime security epoch from the current physical Session,
 * not a caller supplied or cached grade. ENCRYPTED needs level1 or2;
 * AUTHENTICATED needs the explicitly confirmed numeric level2 mechanism.
 * These requirements do not assert a named identity, policy authorization or
 * Bond. Off/rekey/revocation permanently invalidates an old protected fd;
 * each software admission, actual USB commit and RX dequeue checks authority.
 * ACB receipt epochs also reject old RX and cross-epoch PB reassembly.
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
/* Unpublished version3 extension. bind() stages one passive per-connection
 * endpoint; nonblocking connect() stages one active CMTC request and returns
 * EINPROGRESS. CHANNEL_INFO EAGAIN and no POLLOUT until real negotiation.
 * Only CAP_NET_ADMIN can stage; a delegated staged fd has no data Grant yet.
 * Local/remote TCID inputs must be zero: kernel assigns and negotiates them.
 * Ports/AID match an explicitly authorized peer endpoint. Basic only, no QoS
 * guarantee from a preferred SLQI. No security projection or reliable mode.
 */
struct sockaddr_sparklink_dynamic {
	struct sockaddr_sparklink base;
	__u16 source_port, destination_port, aid, mtu, mps;
	__u8 slqi, mode;
	__u32 reserved;
};
#define SPARKLINK_SOCKET_DYNAMIC_VERSION 3
#define SPARKLINK_SOCKET_VERSION 2
#define SPARKLINK_SOCKET_TX 1
#define SPARKLINK_SOCKET_RX 2
#define SPARKLINK_SOCKET_SECURITY_NONE 0
#define SPARKLINK_SOCKET_SECURITY_ENCRYPTED 1
#define SPARKLINK_SOCKET_SECURITY_AUTHENTICATED 2
/* Dynamic protected modes remain unsupported; no implicit downgrade. */
#define SPARKLINK_SOCKET_USER_PI 241
/* Unpublished message context. No trusted identity, Bond or local policy.
 * recvmsg emits one SOL_SPARKLINK/RX_SECURITY ancillary record per datagram,
 * including PEEK/zero-length data. recv() may ignore it. Missing/CTRUNC is not
 * a security fact. epoch belongs to the original ACB receipt, not dequeue time.
 * KNOWN means the sole Owner could correlate that receipt when routing it;
 * CURRENT is rechecked at authorized dequeue. A later key cannot upgrade a
 * queued message. Both flags/grade are observations, never future TX consent.
 * RX records themselves are never accepted as TX ancillary.
 * 40 bytes, identical native/compat; controller/channel identity is local fd.
 */
#define SOL_SPARKLINK 288
#define SPARKLINK_SCM_RX_SECURITY 1
#define SPARKLINK_MESSAGE_SECURITY_VERSION 1
#define SPARKLINK_MESSAGE_SECURITY_KNOWN 1U
#define SPARKLINK_MESSAGE_SECURITY_CURRENT 2U
struct sparklink_message_security {
    __u16 version, size;
    __u32 security;
    __aligned_u64 generation, lifetime, security_epoch;
    __u16 controller, handle;
    __u8 local_tcid, remote_tcid, pi, flags;
};
/* Restriction of an existing fd grant, not authority. Exactly one complete
 * sendmsg record; old epoch or insufficient live mechanism denies admission
 * and every actual USB submission, including subsequent PB fragments.
 * minimum=0 still pins the nonzero epoch. Unknown/duplicate control rejected.
 */
#define SPARKLINK_SCM_TX_CONSTRAINT 2
#define SPARKLINK_SEND_CONSTRAINT_VERSION 1
struct sparklink_send_constraint {
    __u16 version, size;
    __u32 minimum;
    __aligned_u64 generation, lifetime, security_epoch;
    __u16 controller, handle;
    __u8 local_tcid, remote_tcid, pi, reserved;
    __aligned_u64 deadline_monotonic_ns; /* original CLOCK_MONOTONIC, at most5s ahead */
};

/* Prepare an intent through this already-authorized TX fd. Input version1,
 * size48, minimum and original deadline; all identity/reserved fields zero.
 * Output fills scope/current epoch, never renews a Grant or reserves credit.
 * Snapshot alone authorizes nothing: sendmsg must carry the returned intent.
 */
#define SPARKLINK_CHANNEL_PREPARE_TX _IOWR('S', 0xe3, struct sparklink_send_constraint)

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
/* Read-only coherent Host/data/gate -> Session snapshot. No lease/payload or
 * mutation. POLLOUT is software admission, not controller credit availability.
 * peak_reserved counts reservations (including known-never-submitted rollback),
 * pool_exhaustions counts actual native budget refusal, not software EAGAIN.
 * Counters belong to this controller generation and saturate. Active PDU fields
 * describe only this fd's logical channel; debt belongs to physical connection.
 */
struct sparklink_channel_tx_status {
    __u16 version, size, controller, handle;
    __aligned_u64 generation, lifetime;
    __u16 packet_maximum, capacity, outstanding, connection_debt;
    __u16 peak_reserved, queued, queue_limit, busy;
    __u32 active_pdu_bytes, active_pdu_offset, flags, reserved;
    __aligned_u64 pool_exhaustions;
};
#define SPARKLINK_CHANNEL_TX_STATUS_VERSION 1
#define SPARKLINK_CHANNEL_TX_ACTIVE 1U
#define SPARKLINK_CHANNEL_TX_BEGUN 2U
#define SPARKLINK_CHANNEL_TX_STATUS _IOR('S', 0xe1, struct sparklink_channel_tx_status)
/* Read-only per-connection mechanism view through an existing authorized fd.
 * No lease, payload, reset, credit refund or new binding. 64 bytes for native
 * and compat. Success observes this identity, never promises future idleness,
 * callback/reference drain, firmware truth or safe TCID/handle reuse.
 * queues are counted under each queue lock (conservative during concurrent
 * purge); zero is meaningful while Session lock excludes new admissions.
 * Dynamic FAILED entries remain visible tombstones, not successful closes.
 */
struct sparklink_session_tx_status {
	__u16 version, size, controller, handle;
	__aligned_u64 generation, lifetime;
	__u16 capacity, outstanding, connection_debt, queued, active_pdus;
	__u16 dynamic_open, dynamic_pending, dynamic_retired, dynamic_failed, dynamic_allocated;
	__u32 flags;
	__aligned_u64 reserved[2];
};

#define SPARKLINK_SESSION_TX_STATUS_VERSION 1
#define SPARKLINK_SESSION_WORK_RUNNING 1U
#define SPARKLINK_SESSION_WORK_QUEUED 2U
#define SPARKLINK_SESSION_BASE_PENDING 4U
#define SPARKLINK_SESSION_STATE_UNKNOWN 8U
#define SPARKLINK_SESSION_TX_STATUS _IOR('S', 0xe2, struct sparklink_session_tx_status)
#endif
