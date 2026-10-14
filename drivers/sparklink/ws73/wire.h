/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_WS73_WIRE_H
#define _SPARKLINK_WS73_WIRE_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#endif

/* WS73 vendor USB profile, not the standard DLI USB transport. */
#define WS73_WIRE_CONTROL_SIZE 36U
#define WS73_WIRE_CUSTOM_SIZE 864U
#define WS73_WIRE_CUSTOM_DATA_SIZE 140U
#define WS73_WIRE_RX_HEADER_SIZE 92U
#define WS73_WIRE_RX_SLOTS 24U
#define WS73_WIRE_RX_MAX (20U * 1024U)
#define WS73_WIRE_BSLE_SERVICE 5U
#define WS73_WIRE_BSLE_QUEUE 10U
#define WS73_WIRE_SLE_SERVICE 10U
#define WS73_WIRE_SLE_QUEUE 8U

/* Codec functions do not allocate, do I/O, or keep any global state. */
int ws73_wire_control(unsigned char *out, size_t capacity,
		      unsigned int sequence, unsigned int descriptor,
		      unsigned int queue);
int ws73_wire_customize(unsigned char *out, size_t capacity,
			unsigned int sequence, const unsigned char *data,
			size_t size);
int ws73_wire_pm(unsigned char *out, size_t capacity, unsigned int sequence,
		 const unsigned char *data, size_t size);
int ws73_wire_command(unsigned char *out, size_t capacity, unsigned int sequence,
		      unsigned int opcode, const unsigned char *params, size_t size);

/* TX one ACB packet (full or typed PB fragment). Handle is a connection handle, never a TCID.
 * Payload is an opaque DTAP SDU; channel framing belongs above this codec.
 * These helpers do not grant data credit or claim controller acceptance.
 */
int ws73_wire_acb_fragment(unsigned char *out, size_t capacity, unsigned int sequence,
                  unsigned int handle, unsigned int boundary, unsigned int maximum,
                  const unsigned char *payload, size_t size);
int ws73_wire_acb(unsigned char *out, size_t capacity, unsigned int sequence,
		  unsigned int handle, unsigned int maximum,
		  const unsigned char *payload, size_t size);
int ws73_wire_acb_decode(const unsigned char *data, size_t size,
			unsigned int maximum, unsigned int *handle,
			const unsigned char **payload, size_t *payload_size);
int ws73_wire_acb_fragment_decode(const unsigned char *data, size_t size,
			unsigned int maximum, unsigned int *handle,
			unsigned int *boundary, const unsigned char **payload,
			size_t *payload_size);

typedef int (*ws73_wire_consumer)(void *context, unsigned int service,
				 unsigned int queue, const unsigned char *payload,
				 size_t size);
/* Validate the entire aggregate before calling consumer. No padding search. */
int ws73_wire_receive(const unsigned char *data, size_t size,
		      ws73_wire_consumer consumer, void *context);
int ws73_wire_status(const unsigned char *data, size_t size,
		     unsigned int *type, unsigned int *message);

#endif
