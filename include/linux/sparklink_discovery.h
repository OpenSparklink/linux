/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_SPARKLINK_DISCOVERY_H
#define _LINUX_SPARKLINK_DISCOVERY_H

/* Internal typed preparation interface, not a userspace or wire ABI.
 * The caller supplies all values in the selected controller profile, retains
 * immutable input buffers for the call, and owns a disjoint output allocation.
 * No pointer is retained and preparation/validation must not perform I/O.
 */
#define SPARKLINK_DISCOVERY_ADV_START 1U
#define SPARKLINK_DISCOVERY_ADV_STOP 2U
#define SPARKLINK_DISCOVERY_SCAN_START 3U
#define SPARKLINK_DISCOVERY_SCAN_STOP 4U
#define SPARKLINK_DISCOVERY_STEPS_MAX 4U
#define SPARKLINK_DISCOVERY_PARAMS_MAX 255U

struct sparklink_discovery_adv_params {
	unsigned int handle, mode, gt_role;
	unsigned int interval_min, interval_max; /* 125 us, 24-bit */
	unsigned int channel_map, own_address_type, peer_address_type;
	unsigned char own_address[6], peer_address[6];
	unsigned int filter;
	int tx_power;
	unsigned int primary_frame, secondary_frame, secondary_phy;
	unsigned int secondary_pilot, secondary_mcs, secondary_max_skip, sid;
	unsigned int request_notification, max_requests, request_rx_duration;
	unsigned int conn_interval_min, conn_interval_max, conn_max_latency;
	unsigned int supervision_timeout; /* 10 ms */
	unsigned int min_event_length, max_event_length;
};

struct sparklink_discovery_scan_params {
	unsigned int own_address_type, filter, frame_types, active;
	unsigned int interval, window; /* 125 us */
	unsigned int filter_duplicates;
};

struct sparklink_discovery_request {
	unsigned int operation;
	const struct sparklink_discovery_adv_params *advertising;
	const struct sparklink_discovery_scan_params *scanning;
	unsigned int handle, duration, max_events;
	const unsigned char *data;
	unsigned int data_size;
	unsigned int
		scan_response_present; /* 0 or 1; empty response is explicit */
	const unsigned char *scan_response;
	unsigned int scan_response_size;
};

struct sparklink_discovery_step {
	unsigned short opcode, length;
	unsigned char params[SPARKLINK_DISCOVERY_PARAMS_MAX];
};

struct sparklink_discovery_plan {
	unsigned int operation, count, power_step;
	struct sparklink_discovery_step steps[SPARKLINK_DISCOVERY_STEPS_MAX];
};

#endif
