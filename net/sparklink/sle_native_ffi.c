// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/build_bug.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sparklink_native.h>
#include <uapi/linux/sparklink_ioctl.h>

static_assert(sizeof(struct sparklink_native_info) == 32);
static_assert(offsetof(struct sparklink_native_info, features) == 9);
static_assert(offsetof(struct sparklink_native_info, address) == 19);
static_assert(offsetof(struct sparklink_native_info, acb_length) == 26);
static_assert(sizeof(struct sle_controller_event) == 336);
static_assert(offsetof(struct sle_controller_event, payload) == 48);
static_assert(sizeof(struct sle_controller_event_query) == 360);
static_assert(offsetof(struct sle_controller_event_query, event) == 24);

/* The copied operations and retained context outlive the Rust Backend. */
struct sparklink_native_transport {
	struct sparklink_native_ops ops;
	void *context;
};

#include "sle_native_ffi.h"

int sparklink_native_register(const struct sparklink_native_info *info,
			      const struct sparklink_native_ops *ops, void *context,
			      struct sparklink_native_identity *identity)
{
	struct sparklink_native_transport *transport;

	if (!info || !ops || !context || !identity || !ops->get || !ops->put ||
	    !ops->open || !ops->close || !ops->validate_command || !ops->send_command)
		return -EINVAL;
	transport = kmalloc_obj(*transport);
	if (!transport)
		return -ENOMEM;
	if (!try_module_get(ops->owner)) {
		kfree(transport);
		return -ENODEV;
	}
	transport->ops = *ops;
	transport->context = context;
	ops->get(context);
	/* Rust consumes this reference on both success and failure. */
	return sparklink_native_register_rust(info, transport, identity);
}
EXPORT_SYMBOL_GPL(sparklink_native_register);

void sparklink_native_transport_free(struct sparklink_native_transport *transport)
{
	struct module *owner = transport->ops.owner;

	transport->ops.put(transport->context);
	kfree(transport);
	module_put(owner);
}

int sparklink_native_transport_open(struct sparklink_native_transport *transport,
				    u16 id, u64 generation)
{
	return transport->ops.open(transport->context, id, generation);
}

void sparklink_native_transport_close(struct sparklink_native_transport *transport)
{
	transport->ops.close(transport->context);
}

int sparklink_native_transport_validate(struct sparklink_native_transport *transport,
					u16 opcode, const u8 *params, size_t length)
{
	return transport->ops.validate_command(transport->context, opcode, params, length);
}

int sparklink_native_transport_command(struct sparklink_native_transport *transport,
				       u16 opcode, const u8 *params, size_t length)
{
	return transport->ops.send_command(transport->context, opcode, params, length);
}

void sparklink_native_unregister(u16 id, u64 generation)
{
	sparklink_native_unregister_rust(id, generation);
}
EXPORT_SYMBOL_GPL(sparklink_native_unregister);

int sparklink_native_receive(u16 id, u64 generation, const u8 *data, size_t length)
{
	return sparklink_native_receive_rust(id, generation, data, length);
}
EXPORT_SYMBOL_GPL(sparklink_native_receive);

int sparklink_native_event(u16 id, u64 generation, u32 profile, u16 event_code,
			   const u8 *params, size_t length)
{
	return sparklink_native_event_rust(id, generation, profile, event_code, params, length);
}
EXPORT_SYMBOL_GPL(sparklink_native_event);
