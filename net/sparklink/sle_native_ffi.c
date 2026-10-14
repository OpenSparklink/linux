// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/build_bug.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sparklink_native.h>
#include <linux/sparklink_backend.h>
#include <linux/sparklink_channel.h>
#include <uapi/linux/sparklink_ioctl.h>

/* Internal opaque transport helpers called by Rust, not exported UAPI. */
struct sparklink_native_transport;
int sparklink_native_transport_prepare_relay(struct sparklink_native_transport *transport,
    u16 handle, u16 index, const u8 *payload, size_t size, u16 *opcode, u8 *params, size_t capacity);
int sparklink_native_transport_validate_relay(struct sparklink_native_transport *transport,
    u16 opcode, const u8 *params, size_t size);
bool sparklink_native_transport_has_command_ticket(struct sparklink_native_transport *transport);
int sparklink_native_transport_command_ticketed(struct sparklink_native_transport *transport,
    struct sparklink_native_command_ticket *ticket, u16 opcode, const u8 *params, size_t length);

static_assert(sizeof(struct sparklink_native_info) == 32);
static_assert(sizeof(struct sparklink_backend_pending) == 16);
static_assert(sizeof(struct sparklink_native_link_evidence) == 28);
static_assert(offsetof(struct sparklink_native_link_evidence, address) == 20);
static_assert(offsetof(struct sparklink_native_info, features) == 9);
static_assert(offsetof(struct sparklink_native_info, address) == 19);
static_assert(offsetof(struct sparklink_native_info, acb_length) == 26);
static_assert(sizeof(struct sle_controller_event) == 336);
static_assert(offsetof(struct sle_controller_event, payload) == 48);
static_assert(sizeof(struct sle_controller_event_query) == 360);
static_assert(offsetof(struct sle_controller_event_query, event) == 24);

static_assert(sizeof(struct sle_controller_snapshot) == 64);
static_assert(sizeof(struct sle_connection_parameters) == 60);
static_assert(sizeof(struct sparklink_connection_parameters) == 60);
static_assert(sizeof(struct sle_connection_submit) == 128);
static_assert(offsetof(struct sle_connection_submit, expected_lifetime) == 112);
static_assert(sizeof(struct sle_connection_result) == 64);
static_assert(sizeof(struct sparklink_connection_plan) == 40);
static_assert(sizeof(struct sparklink_connection_request) == 72);
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
	/* Immutable validated provider provenance; independent of wire dialect. */
	u32 bus;
	refcount_t references;
	struct sparklink_native_ops ops;
	void *context;
};

#include "sle_native_ffi.h"

static int sparklink_backend_register_identity(const struct sparklink_backend_descriptor *descriptor,
                                  const struct sparklink_native_identity *reserved,
			      struct sparklink_native_identity *identity)
{
	struct sparklink_native_transport *transport;
	struct sparklink_backend_descriptor snapshot;
	struct sparklink_native_ops operations;
	int ret;

	if (!descriptor || !identity)
		return -EINVAL;
	/* Reject a different layout before copying its tail or following ops. */
	if (descriptor->version != SPARKLINK_BACKEND_VERSION ||
	    descriptor->size != sizeof(*descriptor))
		return -EOPNOTSUPP;
	snapshot = *descriptor;
	ret = sparklink_backend_validate(&snapshot);
	if (ret)
		return ret;
	/* Provider owns immutable descriptor/ops for this entire call. The
	 * validator rejects unsupported provenance before dereferencing ops.
	 */
	operations = *snapshot.ops;
	transport = kmalloc_obj(*transport);
	if (!transport)
		return -ENOMEM;
	if (!try_module_get(operations.owner)) {
		kfree(transport);
		return -ENODEV;
	}
	transport->bus = snapshot.bus;
	transport->ops = operations;
	refcount_set(&transport->references, 1);
	transport->context = snapshot.context;
	operations.get(snapshot.context);
	/* Rust consumes this reference on both success and failure. */
	return sparklink_native_register_rust(&snapshot.info, transport, reserved, identity);
}
int sparklink_backend_register(const struct sparklink_backend_descriptor *descriptor,
                              struct sparklink_native_identity *identity)
{
    return sparklink_backend_register_identity(descriptor, NULL, identity);
}
EXPORT_SYMBOL_GPL(sparklink_backend_register);

int sparklink_backend_register_reserved(const struct sparklink_backend_descriptor *descriptor,
                              const struct sparklink_native_identity *reserved,
                              struct sparklink_native_identity *identity)
{
    struct sparklink_native_identity snapshot;

    if (!reserved || !reserved->generation || reserved->id >= 16)
        return -EINVAL;
    snapshot = *reserved;
    return sparklink_backend_register_identity(descriptor, &snapshot, identity);
}
EXPORT_SYMBOL_GPL(sparklink_backend_register_reserved);

int sparklink_backend_reserve(u32 bus, u32 profile, struct sparklink_native_identity *identity)
{
    if (!identity || (bus != SPARKLINK_BACKEND_USB && bus != SPARKLINK_BACKEND_TEST) ||
        (profile != SPARKLINK_NATIVE_WS73_HCC && profile != SPARKLINK_NATIVE_STANDARD_DLI))
        return -EINVAL;
    return sparklink_backend_reserve_rust(bus, profile, identity);
}
EXPORT_SYMBOL_GPL(sparklink_backend_reserve);

void sparklink_backend_cancel(u16 id, u64 generation)
{
    sparklink_backend_cancel_rust(id, generation);
}
EXPORT_SYMBOL_GPL(sparklink_backend_cancel);

int sparklink_backend_pending_update(u16 id, u64 generation, u32 phase, int error)
{
    return sparklink_backend_pending_update_rust(id, generation, phase, error);
}
EXPORT_SYMBOL_GPL(sparklink_backend_pending_update);

int sparklink_backend_pending_query(u16 id, u64 generation, struct sparklink_backend_pending *status)
{
    return sparklink_backend_pending_query_rust(id, generation, status);
}
EXPORT_SYMBOL_GPL(sparklink_backend_pending_query);

u32 sparklink_native_transport_bus(const struct sparklink_native_transport *transport)
{
	return transport->bus;
}

void sparklink_native_transport_get(struct sparklink_native_transport *transport)
{
	refcount_inc(&transport->references);
}

void sparklink_native_transport_free(struct sparklink_native_transport *transport)
{
	struct module *owner = transport->ops.owner;

	if (!refcount_dec_and_test(&transport->references))
		return;
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

int sparklink_native_transport_prepare_connection(struct sparklink_native_transport *transport,
    const struct sparklink_connection_request *request, struct sparklink_connection_plan *plan)
{
    if (!transport->ops.prepare_connection)
        return -EOPNOTSUPP;
    return transport->ops.prepare_connection(transport->context, request, plan);
}

int sparklink_native_transport_validate_connection(struct sparklink_native_transport *transport,
    unsigned int operation, u16 opcode, const u8 *params, size_t length)
{
    if (!transport->ops.validate_connection)
        return -EOPNOTSUPP;
    return transport->ops.validate_connection(transport->context, operation, opcode, params, length);
}

int sparklink_native_transport_prepare_relay(struct sparklink_native_transport *transport,
    u16 handle, u16 index, const u8 *payload, size_t size, u16 *opcode,
    u8 *params, size_t capacity)
{
    if (!transport->ops.prepare_relay)
        return -EOPNOTSUPP;
    return transport->ops.prepare_relay(transport->context, handle, index,
                                      payload, size, opcode, params, capacity);
}
int sparklink_native_transport_validate_relay(struct sparklink_native_transport *transport,
    u16 opcode, const u8 *params, size_t size)
{
    if (!transport->ops.validate_relay)
        return -EOPNOTSUPP;
    return transport->ops.validate_relay(transport->context, opcode, params, size);
}

int sparklink_native_transport_command(struct sparklink_native_transport *transport,
				       u16 opcode, const u8 *params, size_t length)
{
	if (!transport->ops.send_command)
		return -EOPNOTSUPP;
	return transport->ops.send_command(transport->context, opcode, params, length);
}

bool sparklink_native_transport_has_command_ticket(struct sparklink_native_transport *transport)
{
	return transport->ops.send_command_ticketed != NULL;
}

int sparklink_native_transport_command_ticketed(struct sparklink_native_transport *transport,
	struct sparklink_native_command_ticket *ticket, u16 opcode, const u8 *params, size_t length)
{
	if (!transport->ops.send_command_ticketed)
		return -EOPNOTSUPP;
	return transport->ops.send_command_ticketed(transport->context, ticket, opcode, params, length);
}

extern int sparklink_native_command_commit_rust(void *ticket, u16 id, u64 generation,
	int (*submit)(void *context), void *context);

int sparklink_native_command_commit(struct sparklink_native_command_ticket *ticket,
	u16 id, u64 generation, int (*submit)(void *context), void *context)
{
	return sparklink_native_command_commit_rust(ticket, id, generation, submit, context);
}
EXPORT_SYMBOL_GPL(sparklink_native_command_commit);

void sparklink_native_unregister(u16 id, u64 generation)
{
	sparklink_native_unregister_rust(id, generation);
}
EXPORT_SYMBOL_GPL(sparklink_native_unregister);

int sparklink_native_health(u16 id, u64 generation)
{
	return sparklink_native_health_rust(id, generation);
}
EXPORT_SYMBOL_GPL(sparklink_native_health);

int sparklink_native_transport_acb(struct sparklink_native_transport *transport,
				   struct sparklink_native_tx_ticket *ticket, u16 handle, const u8 *data, size_t length)
{
	if (!transport->ops.send_acb)
		return -EOPNOTSUPP;
	return transport->ops.send_acb(transport->context, ticket, handle, data, length);
}

extern int sparklink_native_tx_commit_rust(void *ticket,
                                         int (*submit)(void *context), void *context);
int sparklink_native_tx_commit(struct sparklink_native_tx_ticket *ticket,
                              int (*submit)(void *context), void *context)
{
    return sparklink_native_tx_commit_rust(ticket, submit, context);
}
EXPORT_SYMBOL_GPL(sparklink_native_tx_commit);

bool sparklink_native_transport_has_acb(struct sparklink_native_transport *transport)
{
	return !!transport->ops.send_acb;
}

int sparklink_native_acb_send(u16 id, u64 generation, u64 lifetime, u16 handle,
			    const u8 *data, size_t length)
{
	return sparklink_native_acb_send_rust(id, generation, lifetime, handle, data, length);
}
EXPORT_SYMBOL_GPL(sparklink_native_acb_send);

int sparklink_native_acb_take(u16 id, u64 generation, u64 lifetime, u16 handle,
			    u8 *data, size_t capacity, size_t *length)
{
	return sparklink_native_acb_take_rust(id, generation, lifetime, handle, data, capacity, length);
}
EXPORT_SYMBOL_GPL(sparklink_native_acb_take);

int sparklink_native_acb_limits(u16 id, u64 generation, u64 lifetime, u16 handle,
			      u16 *maximum)
{
	return sparklink_native_acb_limits_rust(id, generation, lifetime, handle, maximum);
}

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

int sparklink_native_link_event(u16 id, u64 generation, u32 profile, u16 event_code,
    const u8 *params, size_t length,
    const struct sparklink_native_link_evidence *evidence)
{
    return sparklink_native_link_event_rust(id, generation, profile,
        event_code, params, length, evidence);
}
EXPORT_SYMBOL_GPL(sparklink_native_link_event);

void sparklink_native_snoop_rx(u16 id, u64 generation, const u8 *data, size_t length)
{
	sparklink_native_snoop_rx_rust(id, generation, data, length);
}
EXPORT_SYMBOL_GPL(sparklink_native_snoop_rx);

void sparklink_native_snoop_tx(u16 id, u64 generation, u16 opcode,
			      const u8 *params, size_t length, int status)
{
	sparklink_native_snoop_tx_rust(id, generation, opcode, params, length, status);
}
EXPORT_SYMBOL_GPL(sparklink_native_snoop_tx);

extern void *sparklink_native_session_get_rust(u16 id, u64 generation, u64 lifetime, u16 handle, u64 epoch, int *error);
extern int sparklink_native_session_status_rust(u16 id, u64 generation, u64 lifetime, u16 handle, u64 epoch);
void *sparklink_native_session_get(u16 id, u64 generation, u64 lifetime, u16 handle, u64 epoch, int *error)
{
    return sparklink_native_session_get_rust(id, generation, lifetime, handle, epoch, error);
}
int sparklink_native_session_status(u16 id, u64 generation, u64 lifetime, u16 handle, u64 epoch)
{
    return sparklink_native_session_status_rust(id, generation, lifetime, handle, epoch);
}

extern int sparklink_native_acb_send_guarded_rust(u16 id, u64 generation, u64 lifetime, u16 handle,
    const u8 *data, size_t length, u64 epoch,
    int (*consent)(void *scope, int (*submit)(void *context), void *context), void *scope);
int sparklink_native_acb_send_guarded(u16 id, u64 generation, u64 lifetime, u16 handle,
    const u8 *data, size_t length, u64 epoch,
    int (*consent)(void *scope, int (*submit)(void *context), void *context), void *scope)
{
    return sparklink_native_acb_send_guarded_rust(id, generation, lifetime, handle, data, length, epoch, consent, scope);
}

extern int sparklink_native_session_admit_rust(u16 id, u64 generation, u64 lifetime, u16 handle,
    u64 epoch, int (*admit)(void *), void *context);
int sparklink_native_session_admit(u16 id, u64 generation, u64 lifetime, u16 handle,
    u64 epoch, int (*admit)(void *), void *context)
{
    return sparklink_native_session_admit_rust(id, generation, lifetime, handle, epoch, admit, context);
}

/* Caller owns the live packet span; only the attributed standard profile accepts
 * it. Core copies/decodes before return. Endpoint/transport owns I/O and joins.
 */
void sparklink_backend_standard_receive(u32 id, u64 generation, const u8 *data,
                                       int length, u8 lane, int status)
{
    sparklink_standard_receive_rust(id, generation, data, length, lane, status);
}
EXPORT_SYMBOL_GPL(sparklink_backend_standard_receive);
