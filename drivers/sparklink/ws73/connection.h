/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WS73_CONNECTION_H
#define WS73_CONNECTION_H
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif
#include <linux/sparklink_connection.h>
int ws73_connection_create(unsigned char *out, size_t capacity,
    const struct sparklink_connection_parameters *parameters);
int ws73_connection_disconnect(unsigned char *out, size_t capacity,
    unsigned int handle, unsigned int reason);
int ws73_connection_validate(unsigned int operation, unsigned int opcode,
    const unsigned char *parameters, size_t size);
int ws73_connection_prepare(const struct sparklink_connection_request *request,
    struct sparklink_connection_plan *out);
#endif
