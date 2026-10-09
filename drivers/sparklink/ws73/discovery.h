/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SPARKLINK_WS73_DISCOVERY_H
#define _SPARKLINK_WS73_DISCOVERY_H

#include "wire.h"

/* Explicit vendor profile. These sizes are not the standard USB dialect.
 * Framing facts: libws73-usb f4d85d0, checked against T/XS 10003-2025
 * sections 8.2/8.3/9.1.19 and communication_nearlink_service f0872df.
 * Independent implementation; no reference source is incorporated.
 * These codecs do not enable Runtime support, attest firmware capability,
 * qualify a board's calibration, or establish real RF operation.
 */
#define WS73_DISC_ADV_PARAM_SIZE 49U
#define WS73_DISC_ADV_DATA_HEADER 3U
#define WS73_DISC_ADV_DATA_MAX 251U
#define WS73_DISC_ADV_ENABLE_SIZE 5U
#define WS73_DISC_SCAN_PARAM_SIZE 8U
#define WS73_DISC_SCAN_ENABLE_SIZE 2U
#define WS73_DISC_REPORT_EVENT 0x180bU
#define WS73_DISC_REPORT_HEADER 23U
#define WS73_DISC_REPORT_DATA_MAX 255U
#define WS73_DISC_REPORT_MAX (WS73_DISC_REPORT_HEADER + WS73_DISC_REPORT_DATA_MAX)

/* A borrowed view of exactly one event parameter body, without A2/event/len.
 * header preserves all vendor bytes, including address types, direct address,
 * PHY fields and the uninterpreted extra byte at offset 20. No reassembly,
 * normalization, invented address type, or discovery-level inference.
 * The pointers are valid only for the lifetime of the caller's input.
 */
struct ws73_discovery_report {
	const unsigned char *header;
	const unsigned char *data;
	unsigned int data_size;
	int rssi; /* signed raw byte; 127 means unavailable in the standard */
};

/* Schema check only, not an authorization to send through Runtime. Complete
 * data operations only; fragmentation and other scan frame types are not
 * implemented. Scan-response 0C04 uses the reference's shared schema but
 * remains independently unverified on our hardware.
 */
int ws73_discovery_validate_command(unsigned int opcode, const unsigned char *params,
				    size_t size);
/* Successful encoders return their exact byte count. Errors leave out intact.
 * Zero is a real parameter value; no board/power/timing defaults are inserted.
 * Input/output buffers must not overlap.
 */
int ws73_discovery_data(unsigned char *out, size_t capacity, unsigned int handle,
			const unsigned char *data, size_t size);
int ws73_discovery_adv_enable(unsigned char *out, size_t capacity, unsigned int enable,
			      unsigned int handle, unsigned int duration,
			      unsigned int max_events);
int ws73_discovery_scan_params(unsigned char *out, size_t capacity,
			       unsigned int own_address_type, unsigned int filter,
			       unsigned int frame_types, unsigned int active,
			       unsigned int interval, unsigned int window);
int ws73_discovery_scan_enable(unsigned char *out, size_t capacity,
			       unsigned int enable, unsigned int filter_duplicates);
/* Exact declared length required, including an empty data field. On error
 * report is unchanged. Unknown vendor bytes remain available to the caller.
 */
int ws73_discovery_report_decode(const unsigned char *params, size_t size,
				 struct ws73_discovery_report *report);

#endif
