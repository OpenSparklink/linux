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

static_assert(sizeof(struct sle_controller_snapshot) == 64);
static_assert(sizeof(struct sle_discovery_submit) == 704);
static_assert(sizeof(struct sle_discovery_result) == 64);
static_assert(sizeof(struct sparklink_discovery_plan) == 1052);
static_assert(sizeof(struct sparklink_discovery_adv_params) == sizeof(struct sle_discovery_adv_config));
static_assert(sizeof(struct sparklink_discovery_scan_params) == sizeof(struct sle_discovery_scan_config));
static_assert(offsetof(struct sparklink_discovery_adv_params, handle) == offsetof(struct sle_discovery_adv_config, handle));
static_assert(offsetof(struct sparklink_discovery_adv_params, mode) == offsetof(struct sle_discovery_adv_config, mode));
static_assert(offsetof(struct sparklink_discovery_adv_params, gt_role) == offsetof(struct sle_discovery_adv_config, gt_role));
static_assert(offsetof(struct sparklink_discovery_adv_params, interval_min) == offsetof(struct sle_discovery_adv_config, interval_min));
static_assert(offsetof(struct sparklink_discovery_adv_params, interval_max) == offsetof(struct sle_discovery_adv_config, interval_max));
static_assert(offsetof(struct sparklink_discovery_adv_params, channel_map) == offsetof(struct sle_discovery_adv_config, channel_map));
static_assert(offsetof(struct sparklink_discovery_adv_params, own_address_type) == offsetof(struct sle_discovery_adv_config, own_address_type));
static_assert(offsetof(struct sparklink_discovery_adv_params, peer_address_type) == offsetof(struct sle_discovery_adv_config, peer_address_type));
static_assert(offsetof(struct sparklink_discovery_adv_params, own_address) == offsetof(struct sle_discovery_adv_config, own_address));
static_assert(offsetof(struct sparklink_discovery_adv_params, peer_address) == offsetof(struct sle_discovery_adv_config, peer_address));
static_assert(offsetof(struct sparklink_discovery_adv_params, filter) == offsetof(struct sle_discovery_adv_config, filter));
static_assert(offsetof(struct sparklink_discovery_adv_params, tx_power) == offsetof(struct sle_discovery_adv_config, tx_power));
static_assert(offsetof(struct sparklink_discovery_adv_params, primary_frame) == offsetof(struct sle_discovery_adv_config, primary_frame));
static_assert(offsetof(struct sparklink_discovery_adv_params, secondary_frame) == offsetof(struct sle_discovery_adv_config, secondary_frame));
static_assert(offsetof(struct sparklink_discovery_adv_params, secondary_phy) == offsetof(struct sle_discovery_adv_config, secondary_phy));
static_assert(offsetof(struct sparklink_discovery_adv_params, secondary_pilot) == offsetof(struct sle_discovery_adv_config, secondary_pilot));
static_assert(offsetof(struct sparklink_discovery_adv_params, secondary_mcs) == offsetof(struct sle_discovery_adv_config, secondary_mcs));
static_assert(offsetof(struct sparklink_discovery_adv_params, secondary_max_skip) == offsetof(struct sle_discovery_adv_config, secondary_max_skip));
static_assert(offsetof(struct sparklink_discovery_adv_params, sid) == offsetof(struct sle_discovery_adv_config, sid));
static_assert(offsetof(struct sparklink_discovery_adv_params, request_notification) == offsetof(struct sle_discovery_adv_config, request_notification));
static_assert(offsetof(struct sparklink_discovery_adv_params, max_requests) == offsetof(struct sle_discovery_adv_config, max_requests));
static_assert(offsetof(struct sparklink_discovery_adv_params, request_rx_duration) == offsetof(struct sle_discovery_adv_config, request_rx_duration));
static_assert(offsetof(struct sparklink_discovery_adv_params, conn_interval_min) == offsetof(struct sle_discovery_adv_config, conn_interval_min));
static_assert(offsetof(struct sparklink_discovery_adv_params, conn_interval_max) == offsetof(struct sle_discovery_adv_config, conn_interval_max));
static_assert(offsetof(struct sparklink_discovery_adv_params, conn_max_latency) == offsetof(struct sle_discovery_adv_config, conn_max_latency));
static_assert(offsetof(struct sparklink_discovery_adv_params, supervision_timeout) == offsetof(struct sle_discovery_adv_config, supervision_timeout));
static_assert(offsetof(struct sparklink_discovery_adv_params, min_event_length) == offsetof(struct sle_discovery_adv_config, min_event_length));
static_assert(offsetof(struct sparklink_discovery_adv_params, max_event_length) == offsetof(struct sle_discovery_adv_config, max_event_length));
static_assert(offsetof(struct sparklink_discovery_scan_params, own_address_type) == offsetof(struct sle_discovery_scan_config, own_address_type));
static_assert(offsetof(struct sparklink_discovery_scan_params, filter) == offsetof(struct sle_discovery_scan_config, filter));
static_assert(offsetof(struct sparklink_discovery_scan_params, frame_types) == offsetof(struct sle_discovery_scan_config, frame_types));
static_assert(offsetof(struct sparklink_discovery_scan_params, active) == offsetof(struct sle_discovery_scan_config, active));
static_assert(offsetof(struct sparklink_discovery_scan_params, interval) == offsetof(struct sle_discovery_scan_config, interval));
static_assert(offsetof(struct sparklink_discovery_scan_params, window) == offsetof(struct sle_discovery_scan_config, window));
static_assert(offsetof(struct sparklink_discovery_scan_params, filter_duplicates) == offsetof(struct sle_discovery_scan_config, filter_duplicates));

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
	    !ops->open || !ops->close || !ops->validate_command || !ops->send_command ||
	    !!ops->prepare_discovery != !!ops->validate_discovery_step)
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

int sparklink_native_transport_prepare(struct sparklink_native_transport *transport,
	const struct sparklink_discovery_request *request,
	struct sparklink_discovery_plan *plan)
{
	if (!transport->ops.prepare_discovery)
		return -EOPNOTSUPP;
	return transport->ops.prepare_discovery(transport->context, request, plan);
}

int sparklink_native_transport_validate_step(struct sparklink_native_transport *transport,
	unsigned int operation, unsigned int step, unsigned int count,
	u16 opcode, const u8 *params, size_t length)
{
	if (!transport->ops.validate_discovery_step)
		return -EOPNOTSUPP;
	return transport->ops.validate_discovery_step(transport->context,
		operation, step, count, opcode, params, length);
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
