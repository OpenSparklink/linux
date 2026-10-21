// SPDX-License-Identifier: GPL-2.0-only
/* Independent field implementation from DLI/reference protocol facts.
 * WS73 v111 has a 27-byte frame-1 create body, not standard V2's additional
 * connection PHY/frame quartet. No reference implementation is incorporated.
 * Preparation grants no raw mutation, credit or connection success.
 */
#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
#else
#include <errno.h>
#include <string.h>
#endif
#include "connection.h"

static unsigned int conn_get16(const unsigned char *p)
{
    return p[0] | (unsigned int)p[1] << 8;
}
static void put16(unsigned char *p, unsigned int value)
{
    p[0] = value; p[1] = value >> 8;
}
int ws73_connection_create(unsigned char *out, size_t capacity,
                           const struct sparklink_connection_parameters *p)
{
    unsigned char candidate[27] = {0};
    if (!out || !p)
        return -EINVAL;
    if (capacity < sizeof(candidate))
        return -ENOSPC;
    if (p->reserved[0] || p->reserved[1] || p->filter > 1 || p->own_address_type > 255 || p->peer_address_type > 255 ||
        p->gt_negotiate > 3 || p->frame != 1 || !p->scan_interval ||
        p->scan_interval > 65535 || !p->scan_window || p->scan_window > p->scan_interval ||
        !p->interval_min || p->interval_min > p->interval_max || p->interval_max > 65535 ||
        p->latency > 65535 || !p->supervision_timeout || p->supervision_timeout > 65535 ||
        p->event_min > p->event_max || p->event_max > 65535)
        return -EINVAL;
    if (!memcmp(p->peer_address, (unsigned char[6]){0}, 6) ||
        !memcmp(p->peer_address, (unsigned char[6]){255,255,255,255,255,255}, 6))
        return -EINVAL;
    candidate[0] = p->filter; candidate[1] = p->own_address_type;
    candidate[2] = p->peer_address_type; memcpy(candidate + 3, p->peer_address, 6);
    candidate[9] = p->gt_negotiate; candidate[10] = p->frame;
    put16(candidate + 11, p->scan_interval); put16(candidate + 13, p->scan_window);
    put16(candidate + 15, p->interval_min); put16(candidate + 17, p->interval_max);
    put16(candidate + 19, p->latency); put16(candidate + 21, p->supervision_timeout);
    put16(candidate + 23, p->event_min); put16(candidate + 25, p->event_max);
    memcpy(out, candidate, sizeof(candidate));
    return sizeof(candidate);
}
int ws73_connection_disconnect(unsigned char *out, size_t capacity,
                               unsigned int handle, unsigned int reason)
{
    unsigned char candidate[3];
    if (!out || handle > 65535 || reason > 255)
        return -EINVAL;
    if (capacity < sizeof(candidate))
        return -ENOSPC;
    put16(candidate, handle); candidate[2] = reason;
    memcpy(out, candidate, sizeof(candidate));
    return sizeof(candidate);
}
int ws73_connection_validate(unsigned int operation, unsigned int opcode,
                             const unsigned char *p, size_t size)
{
    if (size && !p)
        return -EINVAL;
    if (operation == 4 || operation == 5)
        return opcode == (operation == 4 ? 0x180c : 0x1805) && size == 2 ? 0 : -EINVAL;
    if (operation == 2)
        return opcode == 0x1403 && size == 3 ? 0 : -EINVAL;
    if (operation != 1)
        return -EOPNOTSUPP;
    if (opcode != 0x1401 || size != 27)
        return -EINVAL;
    struct sparklink_connection_parameters parameters = {
        .filter = p[0], .own_address_type = p[1], .peer_address_type = p[2],
        .gt_negotiate = p[9], .frame = p[10],
        .scan_interval = conn_get16(p + 11), .scan_window = conn_get16(p + 13),
        .interval_min = conn_get16(p + 15), .interval_max = conn_get16(p + 17),
        .latency = conn_get16(p + 19), .supervision_timeout = conn_get16(p + 21),
        .event_min = conn_get16(p + 23), .event_max = conn_get16(p + 25),
    };
    unsigned char candidate[27];
    memcpy(parameters.peer_address, p + 3, 6);
    return ws73_connection_create(candidate, sizeof(candidate), &parameters) < 0 ? -EINVAL : 0;
}

int ws73_connection_prepare(const struct sparklink_connection_request *request,
                            struct sparklink_connection_plan *out)
{
    struct sparklink_connection_plan candidate = {0};
    int size;

    if (!request || !out)
        return -EINVAL;
    candidate.operation = request->operation;
    if (request->operation == 1) {
        if (request->handle || request->reason)
            return -EINVAL;
        candidate.opcode = 0x1401;
        size = ws73_connection_create(candidate.params, sizeof(candidate.params), &request->parameters);
    } else if (request->operation == 2) {
        if (memcmp(&request->parameters, &(struct sparklink_connection_parameters){0}, sizeof(request->parameters)))
            return -EINVAL;
        candidate.opcode = 0x1403;
        size = ws73_connection_disconnect(candidate.params, sizeof(candidate.params), request->handle, request->reason);
    } else if (request->operation == 4 || request->operation == 5) {
        /* Private provider recipe selectors, not public ConnectionSubmit.
         * No policy mutation; handle bytes are LE16 in this SDK dialect. */
        if (request->handle > 65535 || request->reason ||
            memcmp(&request->parameters, &(struct sparklink_connection_parameters){0}, sizeof(request->parameters)))
            return -EINVAL;
        candidate.opcode = request->operation == 4 ? 0x180c : 0x1805;
        put16(candidate.params, request->handle);
        size = 2;
    } else {
        return -EOPNOTSUPP;
    }
    if (size < 0)
        return size;
    candidate.length = size;
    memcpy(out, &candidate, sizeof(candidate));
    return 0;
}
