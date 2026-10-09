/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_NATIVE_H
#define _LINUX_SPARKLINK_NATIVE_H

#include <linux/types.h>
#include <linux/sparklink_discovery.h>

struct module;

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
 * get/put retain the context across every Backend and in-flight callback.
 * Core owns scheduling/credit/transactions; send only performs one transfer.
 * validate_command is side-effect free and must not perform I/O or acquire
 * Runtime/Host locks. It runs before a transaction/credit is allocated, and
 * again before transfer. The driver owns its dialect and supported commands.
 */
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
	int (*send_command)(void *context, u16 opcode, const u8 *params, size_t length);
};

int sparklink_native_register(const struct sparklink_native_info *info,
			      const struct sparklink_native_ops *ops, void *context,
			      struct sparklink_native_identity *identity);
/* Exact registration only; a stale identity cannot remove a reused index. */
void sparklink_native_unregister(u16 id, u64 generation);
/* Valid during the callback; the core copies data and never retains its pointer.
 * Returns 0 if accepted, -ENODEV for a retired owner, -EPROTO for bad framing.
 * The driver must validate its dialect's management return schema before
 * calling receive; the core checks common framing and does not interpret
 * vendor opcode-specific result layouts. A malformed Complete is not ingress.
 */
int sparklink_native_receive(u16 id, u64 generation, const u8 *data, size_t length);

/* Publish exact driver-validated native event parameters. IRQ-safe; copies
 * into the attributed owner's bounded log before returning. No pointer is
 * retained. Profile must match this registration. Management replies must
 * continue through receive above, not this discovery/notification stream.
 */
int sparklink_native_event(u16 id, u64 generation, u32 profile, u16 event_code,
			   const u8 *params, size_t length);

#endif
