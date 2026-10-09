/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_NATIVE_FFI_H
#define _SPARKLINK_NATIVE_FFI_H

#include <linux/sparklink_native.h>

struct sparklink_native_transport;

int sparklink_native_register_rust(const struct sparklink_native_info *info,
				   struct sparklink_native_transport *transport,
				   struct sparklink_native_identity *identity);
void sparklink_native_unregister_rust(u16 id, u64 generation);
int sparklink_native_receive_rust(u16 id, u64 generation, const u8 *data, size_t length);

void sparklink_native_transport_free(struct sparklink_native_transport *transport);
int sparklink_native_transport_open(struct sparklink_native_transport *transport,
				    u16 id, u64 generation);
void sparklink_native_transport_close(struct sparklink_native_transport *transport);
int sparklink_native_transport_validate(struct sparklink_native_transport *transport,
					u16 opcode, const u8 *params, size_t length);
int sparklink_native_transport_command(struct sparklink_native_transport *transport,
				       u16 opcode, const u8 *params, size_t length);

#endif
