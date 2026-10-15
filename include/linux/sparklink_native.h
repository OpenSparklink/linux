/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_NATIVE_H
#define _LINUX_SPARKLINK_NATIVE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
/* Pure contract selftests use the same declarations and validator. */
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif
#include <linux/sparklink_discovery.h>
#include <linux/sparklink_connection.h>

struct module;

#define SPARKLINK_NATIVE_STANDARD_DLI 0U
#define SPARKLINK_NATIVE_WS73_HCC 1U

/* Internal driver/core interface, not a userspace ABI. Metadata is queried,
 * not a set of defaults. All 80 feature bits and the version tuple survive.
 */
struct sparklink_native_info {
	u32 profile; /* explicit dialect; unsupported profiles fail closed */
	u8 version[5];
	u8 features[10];
	u8 address[6];
	u8 command_credits;
	u16 acb_length;
	u16 icb_length;
	u8 acb_count;
	u8 icb_count;
};

struct sparklink_native_identity {
	u16 id;
	u64 generation;
};

/* open/close/send execute in process context. close must join all callbacks.
 * open does not hold the Runtime state mutex; snapshots remain observable and
 * management acquisition returns -EAGAIN until open succeeds. Open is joined
 * before close, including retirement during open. A failing open must release
 * its own partial resources. Queue unregister on another process-context work
 * item; do not call it synchronously from open/close/send or IRQ callbacks.
 * get/put retain the context across every Backend and in-flight callback.
 * Core owns scheduling/credit/transactions; send only performs one transfer.
 * validate_command is side-effect free and must not perform I/O or acquire
 * Runtime/Host locks. It runs before a transaction/credit is allocated, and
 * again before transfer. The driver owns its dialect and supported commands.
 */
/* Opaque core-owned, process-thread-local ticket. Valid only during send_acb.
 * Driver prepares bytes/URB first, then calls commit exactly once. The submit
 * callback queues one transfer atomically and MUST NOT sleep, decode, wait or
 * reenter Host/Runtime callbacks. Zero means accepted; nonzero means NEVER
 * queued. Completion/wait/kill/join occur after commit returns. The driver
 * must not retain the ticket or return success without a successful commit.
 */
struct sparklink_native_tx_ticket;
struct sparklink_native_command_ticket;
int sparklink_native_command_commit(struct sparklink_native_command_ticket *ticket,
                                   u16 id, u64 generation,
                                   int (*submit)(void *context), void *context);
/* Kernel-private late materialization into a driver-owned temporary buffer.
 * No I/O; actual commit must separately revalidate. Driver wipes after join. */
int sparklink_native_command_materialize(struct sparklink_native_command_ticket *ticket,
                                   u16 id, u64 generation, u8 *params, size_t length);
int sparklink_native_tx_commit(struct sparklink_native_tx_ticket *ticket,
                              int (*submit)(void *context), void *context);

struct sparklink_native_ops {
	struct module *owner;
	void (*get)(void *context);
	void (*put)(void *context);
	int (*open)(void *context, u16 id, u64 generation);
	void (*close)(void *context);
	int (*validate_command)(void *context, u16 opcode, const u8 *params, size_t length);
	/* Optional typed discovery path. Raw validate_command stays unchanged.
	 * Missing callbacks reject typed operations with -EOPNOTSUPP. Prepare
	 * writes a complete plan without I/O; validate checks a kernel-owned
	 * operation/step tag before transfer, never grants raw ioctl permission.
	 */
	int (*prepare_discovery)(void *context,
		const struct sparklink_discovery_request *request,
		struct sparklink_discovery_plan *plan);
	int (*validate_discovery_step)(void *context, unsigned int operation,
		unsigned int step, unsigned int count, u16 opcode,
		const u8 *params, size_t length);
    /* Optional paired callbacks. Missing callbacks reject typed connection.
     * The internal tag never grants raw DLI mutation permission. */
    int (*prepare_connection)(void *context,
        const struct sparklink_connection_request *request,
        struct sparklink_connection_plan *plan);
    int (*validate_connection)(void *context, unsigned int operation,
        u16 opcode, const u8 *params, size_t length);
    /* Internal Host relay only. Missing callbacks reject, never grant raw
     * ioctl authority. Wire layout and finite parameter budget are driver-owned. The returned
     * echo_index names the actual transmitted index, frozen before admission;
     * canonical SMP identity is separate. */
    int (*prepare_relay)(void *context, u16 handle, u16 index,
        const u8 *payload, size_t size, u16 *opcode, u8 *params, size_t capacity,
        u16 *echo_index);
    int (*validate_relay)(void *context, u16 opcode, const u8 *params, size_t size);
	int (*send_command)(void *context, u16 opcode, const u8 *params, size_t length);
	/* Optional atomic command submission. Prepare outside Host locks, then
	 * commit exactly once; wait/kill/join after commit returns. The core checks
	 * the real active reservation and immutable registration at USB queueing.
	 * This is not command Complete or a grant for raw mutation/security APIs.
	 */
	int (*send_command_ticketed)(void *context,
		struct sparklink_native_command_ticket *ticket,
		u16 opcode, const u8 *params, size_t length);
	/* Optional one-transfer ACB path. Core retains identity and Backend;
     * credit and canonical lifetime are checked at actual atomic submission.
     * USB completion does not pay data debt or prove peer delivery. */
    int (*send_acb)(void *context, struct sparklink_native_tx_ticket *ticket,
                    u16 handle, const u8 *data, size_t length);
    /* Typed DLI PB (0 full, 1 first, 2 middle, 3 last), not DTAP SAR. */
    int (*send_acb_fragment)(void *context, struct sparklink_native_tx_ticket *ticket,
                    u16 handle, u8 boundary, const u8 *data, size_t length);
};

/* Providers register through sparklink_backend.h. No legacy registration
 * wrapper: this internal interface has no compatibility commitment. */
/* Exact registration only; a stale identity cannot remove a reused index. */
void sparklink_native_unregister(u16 id, u64 generation);
/* Process-context observation only: 2 healthy Ready, 1 Setup, negative fault
 * or retired identity. Never admits I/O, supplies credits or publishes Ready.
 */
int sparklink_native_health(u16 id, u64 generation);
/* Valid during the callback; the core copies data and never retains its pointer.
 * Returns 0 if accepted, -ENODEV for a retired owner, -EPROTO for bad framing.
 * The driver must validate its dialect's management return schema before
 * calling receive; the core checks common framing and does not interpret
 * vendor opcode-specific result layouts. A malformed Complete is not ingress.
 */
int sparklink_native_receive(u16 id, u64 generation, const u8 *data, size_t length);

/* Internal DTAP/channel seam, NOT a raw userspace ioctl. Buffers are kernel
 * owned and live for the call. Full SDU only, current canonical lifetime.
 * Send is process-context/blocking; take is nonblocking and preserves a packet
 * on -EMSGSIZE. No handle-only legacy send admission or synthetic replies.
 */
int sparklink_native_acb_send(u16 id, u64 generation, u64 lifetime, u16 handle,
			    const u8 *data, size_t length);
int sparklink_native_acb_take(u16 id, u64 generation, u64 lifetime, u16 handle,
			    u8 *data, size_t capacity, size_t *length);
int sparklink_native_acb_limits(u16 id, u64 generation, u64 lifetime, u16 handle,
			      u16 *maximum);

/* Publish exact driver-validated native event parameters. IRQ-safe; copies
 * into the attributed owner's bounded log before returning. No pointer is
 * retained. Profile must match this registration. Management replies must
 * continue through receive above, not this discovery/notification stream.
 */
int sparklink_native_event(u16 id, u64 generation, u32 profile, u16 event_code,
			   const u8 *params, size_t length);

/* Driver-normalized physical link facts, not a userspace ABI. The original
 * event body is retained without projection. kind1 is a connection outcome,
 * kind2 a disconnection outcome. Failed status never establishes/removes a
 * link. All fields are explicit; extensions remain in the original body.
 * A driver delivering physical link outcomes must use this atomic ingress,
 * rather than log-only sparklink_native_event. No mutation command permission
 * or command-accepted -> connected inference follows from either function.
 */
struct sparklink_native_link_evidence {
    u32 kind, status, handle, role, address_type;
    u8 address[6], reserved[2];
};
int sparklink_native_link_event(u16 id, u64 generation, u32 profile, u16 event_code,
    const u8 *params, size_t length,
    const struct sparklink_native_link_evidence *evidence);

/* Optional observational hooks. No allocation, I/O or protocol admission;
 * errors/drops must never alter transport behavior. Buffers are copied now.
 * RX is one HCC-validated WS73 DLI slot, before DLI schema/domain decoding.
 * TX is the WS73 A1 command and actual blocking transfer result, not Complete.
 */
void sparklink_native_snoop_rx(u16 id, u64 generation, const u8 *data, size_t length);
void sparklink_native_snoop_tx(u16 id, u64 generation, u16 opcode,
			      const u8 *params, size_t length, int status);

/* Session/channel consent is held through the actual atomic queue call.
 * Scope and immutable bytes remain live until the blocking callback joins. */
int sparklink_native_acb_send_guarded(u16 id, u64 generation, u64 lifetime, u16 handle,
    const u8 *data, size_t length, u64 epoch,
    int (*consent)(void *scope, int (*submit)(void *context), void *context), void *scope);
int sparklink_native_acb_fragment_guarded(u16 id, u64 generation, u64 lifetime, u16 handle, u8 boundary,
    const u8 *data, size_t length, u64 epoch,
    int (*consent)(void *scope, int (*submit)(void *context), void *context), void *scope);
#endif
