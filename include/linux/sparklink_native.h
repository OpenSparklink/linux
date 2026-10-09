/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_NATIVE_H
#define _LINUX_SPARKLINK_NATIVE_H

#include <linux/types.h>

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
 */
struct sparklink_native_ops {
	struct module *owner;
	void (*get)(void *context);
	void (*put)(void *context);
	int (*open)(void *context, u16 id, u64 generation);
	void (*close)(void *context);
	int (*send_command)(void *context, u16 opcode, const u8 *params, size_t length);
};

int sparklink_native_register(const struct sparklink_native_info *info,
			      const struct sparklink_native_ops *ops, void *context,
			      struct sparklink_native_identity *identity);
/* Exact registration only; a stale identity cannot remove a reused index. */
void sparklink_native_unregister(u16 id, u64 generation);
/* Valid during the callback; the core copies data and never retains its pointer.
 * Returns 0 if accepted, -ENODEV for a retired owner, -EPROTO for bad framing.
 */
int sparklink_native_receive(u16 id, u64 generation, const u8 *data, size_t length);

#endif
