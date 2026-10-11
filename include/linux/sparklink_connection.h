/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_CONNECTION_H
#define _LINUX_SPARKLINK_CONNECTION_H
/* Internal typed request, not wire or userspace ABI. Values are explicit.
 * Preparation/validation must not retain pointers, acquire Host or do I/O. */
struct sparklink_connection_parameters {
    unsigned int filter, own_address_type, peer_address_type;
    unsigned char peer_address[6], reserved[2];
    unsigned int gt_negotiate, frame;
    unsigned int scan_interval, scan_window, interval_min, interval_max;
    unsigned int latency, supervision_timeout, event_min, event_max;
};
struct sparklink_connection_request {
    unsigned int operation, handle, reason;
    struct sparklink_connection_parameters parameters;
};
struct sparklink_connection_plan {
    unsigned int operation;
    unsigned short opcode, length;
    unsigned char params[32];
};
#endif
