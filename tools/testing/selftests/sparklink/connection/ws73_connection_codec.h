/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WS73_CONNECTION_CODEC_STAGING_H
#define WS73_CONNECTION_CODEC_STAGING_H
#include <stddef.h>

/* Staging protocol contract, not linked into a production driver. All values
 * are supplied explicitly by the caller; this is not an ioctl or capability.
 */
struct ws73_connection_parameters {
    unsigned int filter, own_address_type, peer_address_type;
    unsigned char peer_address[6];
    unsigned int gt_negotiate, frame;
    unsigned int scan_interval, scan_window, interval_min, interval_max;
    unsigned int latency, supervision_timeout, event_min, event_max;
};
int ws73_connection_create(unsigned char *out, size_t capacity,
                           const struct ws73_connection_parameters *parameters);
int ws73_connection_disconnect(unsigned char *out, size_t capacity,
                               unsigned int handle, unsigned int reason);
int ws73_connection_validate(unsigned int operation, unsigned int opcode,
                             const unsigned char *parameters, size_t size);
#endif
