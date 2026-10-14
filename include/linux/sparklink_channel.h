/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_CHANNEL_H
#define _LINUX_SPARKLINK_CHANNEL_H
/* Internal Runtime-owned session references; no public userspace ABI. */
#include <linux/types.h>
void *sl_connection_session_create(u16 controller, u64 generation, u64 lifetime, u16 handle, u64 epoch, u16 maximum);
void sl_connection_session_get(void *session);
void sl_connection_session_put(void *session);
void sl_connection_session_stop(void *session, int error);
void *sparklink_native_session_get(u16 controller, u64 generation, u64 lifetime, u16 handle, u64 epoch, int *error);
int sparklink_native_session_status(u16 controller, u64 generation, u64 lifetime, u16 handle, u64 epoch);
int sparklink_native_session_admit(u16 id, u64 generation, u64 lifetime, u16 handle,
    u64 epoch, int (*admit)(void *), void *context);
struct sparklink_credit_snapshot {
    u16 maximum, capacity, outstanding, connection_debt, peak_reserved, reserved;
    u32 padding;
    u64 pool_exhaustions;
};
int sparklink_native_session_inspect(u16 id,u64 generation,u64 lifetime,u16 handle,u64 epoch,
    int (*inspect)(const struct sparklink_credit_snapshot *,void *),void *context);
int sl_channel_socket_init(void);
void sl_channel_socket_exit(void);
#endif
