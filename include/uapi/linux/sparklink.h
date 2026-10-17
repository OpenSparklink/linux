/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Unpublished registry-only Generic Netlink ABI. Controller operations and
 * events use identity-bound Native APIs, not a default-controller projection.
 */
#ifndef _UAPI_LINUX_SPARKLINK_H
#define _UAPI_LINUX_SPARKLINK_H
#include <linux/types.h>
#define SPARKLINK_GENL_NAME "sparklink"
#define SPARKLINK_GENL_VERSION 2

enum {
	SPARKLINK_CMD_UNSPEC = 0,
	SPARKLINK_CMD_GET_REGISTRY_COUNT = 1, /* Registered entries, not Ready. */
	/* Removed command numbers are not reused. */
	SPARKLINK_CMD_GET_VERSION = 28,
	__SPARKLINK_CMD_MAX = 29,
};
#define SPARKLINK_CMD_MAX (__SPARKLINK_CMD_MAX - 1)
enum {
	SPARKLINK_ATTR_UNSPEC = 0,
	/* Removed attribute numbers are not reused. */
	SPARKLINK_ATTR_DEV_COUNT = 5, /* u32 */
	SPARKLINK_ATTR_PROTO_VERSION = 6, /* u32; software ABI, not firmware. */
	SPARKLINK_ATTR_GENL_VERSION = 7, /* u32 */
	__SPARKLINK_ATTR_MAX = 8,
};
#define SPARKLINK_ATTR_MAX (__SPARKLINK_ATTR_MAX - 1)
/* ---------------------------------------------------------------------------
 * Event types (same as sle_event.rs)
 * ---------------------------------------------------------------------------
 */

enum sparklink_event_type {
	/* Core events */
	SPARKLINK_EVT_CONN_STATE	= 0x01,
	SPARKLINK_EVT_ADV_REPORT	= 0x02,
	SPARKLINK_EVT_DATA_RECEIVED	= 0x03,
	SPARKLINK_EVT_SECURITY_CHANGED	= 0x04,
	SPARKLINK_EVT_POWER_CHANGED	= 0x05,
	SPARKLINK_EVT_HARDWARE_ERROR	= 0x06,
	SPARKLINK_EVT_CMD_COMPLETE	= 0x07,
	SPARKLINK_EVT_CMD_STATUS	= 0x08,
	SPARKLINK_EVT_BROADCAST_END	= 0x09,
	SPARKLINK_EVT_PHY_UPDATE	= 0x0A,
	SPARKLINK_EVT_CONN_PARAM_UPDATE	= 0x0B,
	SPARKLINK_EVT_DATA_LEN_CHANGE	= 0x0C,
	SPARKLINK_EVT_DATA_BUF_OVERFLOW	= 0x0D,
	SPARKLINK_EVT_PEER_CONN_PARAM_REQ = 0x0E,

	/* T/XS 10003-2025 §9.1.7-§9.1.11 */
	SPARKLINK_EVT_POWER_CHANGE_REPORT = 0x0F,
	SPARKLINK_EVT_NUM_COMPLETED_PKTS  = 0x10,
	SPARKLINK_EVT_ENCRYPT_PARAM_REQ	  = 0x11,

	/* T/XS 10003-2025 §9.1.13-§9.1.21 */
	SPARKLINK_EVT_CTRL_SIGNAL_DATA	= 0x12,
	SPARKLINK_EVT_READ_PEER_FEATURES = 0x13,
	SPARKLINK_EVT_READ_PEER_VERSION	= 0x14,
	SPARKLINK_EVT_READ_PEER_POWER	= 0x15,
	SPARKLINK_EVT_INQUIRY_REQ_REPORT = 0x16,

	/* T/XS 10003-2025 §9.1.22-§9.1.32 (pairing) */
	SPARKLINK_EVT_PAIR_REQUEST	= 0x17,
	SPARKLINK_EVT_PAIR_INFO_EXCH_REQ = 0x18,
	SPARKLINK_EVT_PAIR_INFO_REPORT	= 0x19,
	SPARKLINK_EVT_PAIR_OPTION_REPORT = 0x1A,
	SPARKLINK_EVT_PEER_PUBKEY_REPORT = 0x1B,
	SPARKLINK_EVT_PAIR_EXT_DATA	= 0x1C,
	SPARKLINK_EVT_KEYPRESS_NOTIFY	= 0x1D,
	SPARKLINK_EVT_PAIR_RANDOM_REPORT = 0x1E,
	SPARKLINK_EVT_PAIR_CONFIRM_REPORT = 0x1F,
	SPARKLINK_EVT_DH_KEY_CHECK_REPORT = 0x20,
	SPARKLINK_EVT_PAIR_FAILURE_REPORT = 0x21,

	/* T/XS 10003-2025 §9.1.33-§9.1.39 (narrowband measurement) */
	SPARKLINK_EVT_NB_MEAS_INFO	= 0x22,
	SPARKLINK_EVT_NB_MEAS_STATE_CHG = 0x23,
	SPARKLINK_EVT_NB_MEAS_PARAM	= 0x24,
	SPARKLINK_EVT_LOCAL_NB_MEAS_CAP = 0x25,
	SPARKLINK_EVT_PEER_NB_MEAS_CAP = 0x26,
	SPARKLINK_EVT_MEAS_STATE_CHG	= 0x27,
	SPARKLINK_EVT_MEAS_QUANTITY	= 0x28,

	/* T/XS 10003-2025 §9.1.40-§9.1.45 (SLB) */
	SPARKLINK_EVT_SLB_ADV_REPORT	= 0x29,
	SPARKLINK_EVT_SLB_CONN_COMPLETE	= 0x2A,
	SPARKLINK_EVT_SLB_UCAST_CH_DONE = 0x2B,
	SPARKLINK_EVT_SLB_UCAST_CH_UPD	= 0x2C,
	SPARKLINK_EVT_SLB_CH_DELETE	= 0x2D,
	SPARKLINK_EVT_SLB_NUM_COMP_PKTS	= 0x2E,

	/* T/XS 10003-2025 §9.1.46-§9.1.51 (sync link) */
	SPARKLINK_EVT_TIME_SYNC_STATUS	= 0x2F,
	SPARKLINK_EVT_TIME_SYNC_REQUEST	= 0x30,
	SPARKLINK_EVT_SYNC_UCAST_SETUP_REQ  = 0x31,
	SPARKLINK_EVT_SYNC_UCAST_SETUP_DONE = 0x32,
	SPARKLINK_EVT_SYNC_MCAST_SETUP_REQ  = 0x33,
	SPARKLINK_EVT_SYNC_MCAST_SETUP_DONE = 0x34,
};

/* ---------------------------------------------------------------------------
 * Connection states
 * ---------------------------------------------------------------------------
 */

enum sparklink_conn_state {
	SPARKLINK_CONN_IDLE		= 0,
	SPARKLINK_CONN_CONNECTING	= 1,
	SPARKLINK_CONN_CONNECTED	= 2,
	SPARKLINK_CONN_DISCONNECTING	= 3,
};

/* ---------------------------------------------------------------------------
 * Power states
 * ---------------------------------------------------------------------------
 */

enum sparklink_pm_state {
	SPARKLINK_PM_ACTIVE		= 0,
	SPARKLINK_PM_SNIFF		= 1,
	SPARKLINK_PM_IDLE		= 2,
	SPARKLINK_PM_SUSPENDED		= 3,
};

/* ---------------------------------------------------------------------------
 * Security states
 * ---------------------------------------------------------------------------
 */

enum sparklink_sec_state {
	SPARKLINK_SEC_NONE		= 0,
	SPARKLINK_SEC_PAIRING		= 1,
	SPARKLINK_SEC_PAIRED		= 2,
	SPARKLINK_SEC_ENCRYPTED		= 3,
};

/* ---------------------------------------------------------------------------
 * Pairing methods
 * ---------------------------------------------------------------------------
 */

enum sparklink_pair_method {
	SPARKLINK_PAIR_NONE		= 0,
	SPARKLINK_PAIR_JUST_WORKS	= 1,
	SPARKLINK_PAIR_PSK		= 2,
};

/* ---------------------------------------------------------------------------
 * Discovery levels (T/XS 20001-2025)
 * ---------------------------------------------------------------------------
 */

enum sparklink_discovery_level {
	SPARKLINK_DISC_INVISIBLE	= 0,
	SPARKLINK_DISC_GENERAL		= 1,
	SPARKLINK_DISC_PRIORITY		= 2,
	SPARKLINK_DISC_PAIRED_ONLY	= 3,
	SPARKLINK_DISC_DESIGNATED	= 4,
};

/* ---------------------------------------------------------------------------
 * DLI transport bus types
 * ---------------------------------------------------------------------------
 */

enum sparklink_dli_bus {
	SPARKLINK_BUS_VIRTUAL		= 0,
	SPARKLINK_BUS_UART		= 1,
	SPARKLINK_BUS_SPI		= 2,
	SPARKLINK_BUS_SDIO		= 3,
	SPARKLINK_BUS_USB		= 4,
	SPARKLINK_BUS_MMIO		= 5,
	/* Test provenance, not physical hardware or a qualified VirtualBackend. */
	SPARKLINK_BUS_TEST		= 6,
};

/* ---------------------------------------------------------------------------
 * DLI packet type indicators (T/XS 10003-2025 Table 1)
 * ---------------------------------------------------------------------------
 */

enum sparklink_dli_pkt_type {
	SPARKLINK_DLI_PKT_COMMAND	= 0xA1,
	SPARKLINK_DLI_PKT_EVENT		= 0xA2,
	SPARKLINK_DLI_PKT_ASYNC_UCAST	= 0xA3,
	SPARKLINK_DLI_PKT_SYNC_UCAST	= 0xA4,
	SPARKLINK_DLI_PKT_ASYNC_MCAST	= 0xA5,
};

/* ---------------------------------------------------------------------------
 * DLI event codes (T/XS 10003-2025 §9.1)
 *
 * These are the 2-byte event identifiers in the DLI wire protocol,
 * distinct from the sparklink_event_type values used in the kernel
 * event subsystem.
 * ---------------------------------------------------------------------------
 */

enum sparklink_dli_event_code {
	SPARKLINK_DLI_EVT_CMD_STATUS		= 0x0001, /* 9.1.1 */
	SPARKLINK_DLI_EVT_CMD_COMPLETE		= 0x0002, /* 9.1.2 */
	SPARKLINK_DLI_EVT_DATA_LEN_CHANGE	= 0x0003, /* 9.1.3 */
	SPARKLINK_DLI_EVT_BROADCAST_END		= 0x0004, /* 9.1.4 */
	SPARKLINK_DLI_EVT_DISCONNECTED		= 0x0005, /* 9.1.5 */
	SPARKLINK_DLI_EVT_PEER_CONN_PARAM_REQ	= 0x0007, /* 9.1.6 */
	SPARKLINK_DLI_EVT_TX_POWER_CHANGE	= 0x0008, /* 9.1.7 */
	SPARKLINK_DLI_EVT_NUM_COMPLETED_PKTS	= 0x0009, /* 9.1.8 */
	SPARKLINK_DLI_EVT_HW_ERROR		= 0x000A, /* 9.1.9 */
	SPARKLINK_DLI_EVT_DATA_BUF_OVERFLOW	= 0x000B, /* 9.1.10 */
	SPARKLINK_DLI_EVT_ENCRYPT_PARAM_REQ	= 0x000E, /* 9.1.11 */
	SPARKLINK_DLI_EVT_ENCRYPT_STATE_CHANGE	= 0x0011, /* 9.1.12 */
	SPARKLINK_DLI_EVT_CTRL_SIGNAL_DATA	= 0x0014, /* 9.1.13 */
	SPARKLINK_DLI_EVT_CONN_ESTABLISHED	= 0x0015, /* 9.1.14 */
	SPARKLINK_DLI_EVT_READ_PEER_FEATURES	= 0x0016, /* 9.1.15 */
	SPARKLINK_DLI_EVT_READ_PEER_VERSION	= 0x0017, /* 9.1.16 */
	SPARKLINK_DLI_EVT_PHY_PARAM_UPDATE	= 0x0018, /* 9.1.17 */
	SPARKLINK_DLI_EVT_CONN_PARAM_UPDATE	= 0x0019, /* 9.1.18 */
	SPARKLINK_DLI_EVT_BROADCAST_REPORT	= 0x001A, /* 9.1.19 */
	SPARKLINK_DLI_EVT_READ_PEER_TX_POWER	= 0x001B, /* 9.1.20 */
	SPARKLINK_DLI_EVT_INQUIRY_REQ_REPORT	= 0x001C, /* 9.1.21 */
	SPARKLINK_DLI_EVT_PAIR_REQUEST		= 0x001D, /* 9.1.22 */
	SPARKLINK_DLI_EVT_PAIR_INFO_EXCHANGE	= 0x001E, /* 9.1.23 */
	SPARKLINK_DLI_EVT_PAIR_INFO_REPORT	= 0x001F, /* 9.1.24 */
	SPARKLINK_DLI_EVT_PAIR_OPTION_REPORT	= 0x0020, /* 9.1.25 */
	SPARKLINK_DLI_EVT_REMOTE_PUBLIC_KEY	= 0x0021, /* 9.1.26 */
	SPARKLINK_DLI_EVT_PAIR_EXT_DATA		= 0x0022, /* 9.1.27 */
	SPARKLINK_DLI_EVT_KEY_NOTIFY		= 0x0023, /* 9.1.28 */
	SPARKLINK_DLI_EVT_PAIR_RANDOM		= 0x0024, /* 9.1.29 */
	SPARKLINK_DLI_EVT_PAIR_CONFIRM		= 0x0025, /* 9.1.30 */
	SPARKLINK_DLI_EVT_DHKEY_CHECK		= 0x0026, /* 9.1.31 */
	SPARKLINK_DLI_EVT_PAIR_FAILED		= 0x0027, /* 9.1.32 */
	SPARKLINK_DLI_EVT_NB_FH_MEAS_INFO	= 0x0028, /* 9.1.33 */
	SPARKLINK_DLI_EVT_NB_FH_MEAS_STATE	= 0x0029, /* 9.1.34 */
	SPARKLINK_DLI_EVT_NB_FH_MEAS_PARAM	= 0x002A, /* 9.1.35 */
	SPARKLINK_DLI_EVT_LOCAL_NB_FH_CAP	= 0x002B, /* 9.1.36 */
	SPARKLINK_DLI_EVT_PEER_NB_FH_CAP	= 0x002C, /* 9.1.37 */
	SPARKLINK_DLI_EVT_MEAS_STATE_CHANGE	= 0x002D, /* 9.1.38 */
	SPARKLINK_DLI_EVT_MEAS_REPORT		= 0x002E, /* 9.1.39 */
	SPARKLINK_DLI_EVT_SLB_BROADCAST_REPORT	= 0x002F, /* 9.1.40 */
	SPARKLINK_DLI_EVT_SLB_CONN_ESTABLISHED	= 0x0030, /* 9.1.41 */
	SPARKLINK_DLI_EVT_SLB_UC_CH_ESTABLISHED = 0x0031, /* 9.1.42 */
	SPARKLINK_DLI_EVT_SLB_UC_CH_UPDATED	= 0x0032, /* 9.1.43 */
	SPARKLINK_DLI_EVT_SLB_CH_DELETED	= 0x0033, /* 9.1.44 */
	SPARKLINK_DLI_EVT_SLB_NUM_COMPLETED	= 0x0034, /* 9.1.45 */
	SPARKLINK_DLI_EVT_TIME_SYNC_UPDATE	= 0x0035, /* 9.1.46 */
	SPARKLINK_DLI_EVT_TIME_SYNC_REQUEST	= 0x0036, /* 9.1.47 */
	SPARKLINK_DLI_EVT_SYNC_UC_CONN_REQ	= 0x0038, /* 9.1.48 */
	SPARKLINK_DLI_EVT_SYNC_UC_CONN_DONE	= 0x0039, /* 9.1.49 */
	SPARKLINK_DLI_EVT_SYNC_MC_CONN_REQ	= 0x003A, /* 9.1.50 */
	SPARKLINK_DLI_EVT_SYNC_MC_CONN_DONE	= 0x003B, /* 9.1.51 */
};

#endif /* _UAPI_LINUX_SPARKLINK_H */
