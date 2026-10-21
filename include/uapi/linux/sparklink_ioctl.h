/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * SparkLink (NearLink) ioctl interface definitions.
 *
 * Canonical UAPI header for the /dev/sparklink character device.
 * All ioctl constants, data structures, and event types used by
 * userspace programs are defined here.
 *
 * Copyright (C) 2025 SparkLink for Linux Contributors
 */
#ifndef _UAPI_LINUX_SPARKLINK_IOCTL_H
#define _UAPI_LINUX_SPARKLINK_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* =========================================================================
 * Data structures
 * =========================================================================
 */

/* --- Device management -------------------------------------------------- */

struct sci_dev_info {
	__u16 index;
	__u8  state;
	__u8  bus;
	__u8  addr[6];
	__u8  name[32];
	__u8  _reserved[24];
};


struct sle_mgmt_stats {
	__u16 pending;
	__u16 _pad;
	__u32 total_submitted;
	__u32 total_resolved;
	__u32 total_timeouts;
};


/* Explicitly selected registration. Native Ready means actual metadata and
 * both initialization stop operations completed, with no Host fault. It is
 * not an RF/calibration attestation. valid_fields bit 0 identifies the full
 * queried native tuple; profile0 preserves its queried tuple without claiming a connected-data path.
 */
#define SLE_CONTROLLER_SNAPSHOT_VERSION 1U
#define SLE_CONTROLLER_READY 1U
#define SLE_CONTROLLER_SETUP 2U
#define SLE_CONTROLLER_FAULT 4U
#define SLE_CONTROLLER_FULL_METADATA 1U
struct sle_controller_snapshot {
	__aligned_u64 generation;
	__u32 version;
	__u32 flags;
	__u32 profile;
	__u32 valid_fields;
	__u16 dev_index;
	__u8 bus;
	__u8 command_credits;
	__u16 acb_length;
	__u16 icb_length;
	__u8 acb_count;
	__u8 icb_count;
	__u8 version_tuple[5];
	__u8 features[10];
	__u8 address[6];
	__u8 reserved_byte;
	__s32 error;
	__u8 reserved[4];
};
#define SL_IOCTL_CONTROLLER_SNAPSHOT _IOWR(SL_MAGIC, 0x8a, struct sle_controller_snapshot)

/* Core registration state, not Host Ready. Query without selecting a Runtime.
 * Input: version=1, dev_index, generation (0 probes), all other fields zero.
 * Snapshot linearizes under the registry lock; generation names that observation.
 * Phase/error are raw provider diagnostics only while Pending/Fault.
 */
#define SLE_REGISTRATION_VERSION 1U
#define SLE_REGISTRATION_PENDING 1U
#define SLE_REGISTRATION_FAULT 2U
#define SLE_REGISTRATION_INSTALLED 3U
#define SLE_REGISTRATION_RETIRING 4U
struct sle_registration_snapshot {
	__aligned_u64 generation;
	__u32 version;
	__u32 state;
	__u32 profile;
	__u32 phase;
	__s32 error;
	__u16 dev_index;
	__u8 bus;
	__u8 reserved_byte;
	__u8 reserved[8];
};
#define SL_IOCTL_REGISTRATION_SNAPSHOT _IOWR(SL_MAGIC, 0x9f, struct sle_registration_snapshot)


/* Matched final Complete receipt in CLOCK_BOOTTIME ns. Zero until success.
 * Observational, explicit generation/request; does not consume event history.
 * The existing sle_discovery_result and ioctl remain unchanged. */
struct sle_discovery_timing {
 __aligned_u64 generation;
 __aligned_u64 request_id;
 __aligned_u64 completed_boottime_ns;
 __u32 version;
 __u32 flags;
 __u32 operation;
 __u32 state;
 __u16 dev_index;
 __u16 opcode;
 __u8 status;
 __u8 reserved[3];
};
#define SL_IOCTL_DISCOVERY_TIMING _IOWR(SL_MAGIC, 0x8f, struct sle_discovery_timing)


/* Versioned, non-destructive native controller event stream. All integer
 * fields use the same native-endian convention as existing SparkLink ioctls.
 * payload contains exact validated controller parameters, not USB/HCC headers.
 * Profile describes their dialect; no discovery fields are normalized here.
 */
#define SLE_CONTROLLER_EVENT_VERSION 1U
#define SLE_CONTROLLER_EVENT_PAYLOAD_MAX 288U
#define SLE_CONTROLLER_EVENT_PROFILE_WS73_HCC 1U

struct sle_controller_event {
	__aligned_u64 seq;             /* starts at 1 per registration */
	__aligned_u64 generation;      /* immutable registration identity */
	__aligned_u64 timestamp_ns;    /* CLOCK_BOOTTIME at receipt */
	__aligned_u64 lost;            /* overwritten entries after requested cursor */
	__u32 profile;
	__u16 dev_index;
	__u16 event_code;
	__u16 payload_len;
	__u16 flags;                   /* zero in version 1 */
	__u32 _reserved;               /* zero */
	__u8 payload[SLE_CONTROLLER_EVENT_PAYLOAD_MAX];
};

struct sle_controller_event_query {
	__aligned_u64 after_seq;       /* caller-owned cursor, 0 starts oldest retained */
	__aligned_u64 generation;      /* 0 only with after_seq=0; otherwise exact identity */
	__u32 version;                 /* SLE_CONTROLLER_EVENT_VERSION */
	__u32 flags;                   /* input must be zero */
	struct sle_controller_event event; /* output only; ignored on input */
};

/* GET is nonblocking: EAGAIN means no newer event, ENODEV a retired/mismatched
 * registration, EINVAL a future cursor/flags, EOPNOTSUPP an unknown version.
 * No shared dequeue: independent readers can request the same sequence.
 * GET subscribes this fd's poll to this registration's native stream, even
 * on EAGAIN. read(2) is unsupported; use GET for complete records. Poll without a selected
 * subscription reports POLLERR.
 * DEV_SELECT resets this poll subscription. Errors never advance the cursor.
 * Management replies continue through their dedicated transaction path.
 */


/* =========================================================================
 * IOCTL magic and command definitions
 * =========================================================================
 */

#define SL_MAGIC	'S'

/* Retired unpublished raw operation numbers;never reused:
 * 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x20, 0x21, 0x22, 0x23, 0x24, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x80, 0x81, 0x83, 0x84, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0xa0, 0xa1, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xc0, 0xc1, 0xc2, 0xc3
 * Historical encodings/layouts live only in selftests/retired-raw-uapi.
 */


/* 0x01/0x02: removed unpublished no-op registration commands; not reused. */
#define SL_IOCTL_DEV_COUNT		_IOR(SL_MAGIC, 0x03, __u32)
#define SL_IOCTL_DEV_INFO		_IOR(SL_MAGIC, 0x04, struct sci_dev_info)
#define SL_IOCTL_DEV_LIST		_IOR(SL_MAGIC, 0x06, __u16)

/**
 * SL_IOCTL_DEV_SELECT - Set per-fd device affinity.
 *
 * Bind this open File to one exact registration owner. dup/fork/SCM_RIGHTS
 * share this File binding; no implicit/global controller route exists.
 * A live ownership lease forbids rebinding until its cleanup completes.
 *
 * @arg: __s16  -1 = clear this File binding/observers; >= 0 = bind device id.
 */
#define SL_IOCTL_DEV_SELECT		_IOW(SL_MAGIC, 0x07, __s16)

/**
 * SL_IOCTL_DEV_GET_ACTIVE - Get the effective device for this fd.
 *
 * Returns this File target id even if retired; it does not assert Ready.
 * 0xFFFF means this File is unselected.
 *
 * @arg: __u16 (output)
 */
#define SL_IOCTL_DEV_GET_ACTIVE		_IOR(SL_MAGIC, 0x08, __u16)


/* Removed unpublished SSAP ioctls 0x50..0x5f, 0x6f, 0x72; not reused. */


/* --- DLI controller ----------------------------------------------------- */

#define SL_IOCTL_MGMT_STATS		_IOR(SL_MAGIC, 0x85, struct sle_mgmt_stats)


/* Versioned, per-fd-bound typed controller discovery operations.
 * Select a device first. Result request_id=0/generation=0 probes identity and
 * radio state. Submit requires the returned generation and a caller-chosen
 * nonzero request_id (unique while retained); _IOW has no post-submit copyout.
 * Successful ioctl means accepted, never radio enabled. Results are copied
 * non-destructively; 64 records retained, oldest terminal results may evict.
 * Nonterminal records never evict. Wrong generation/retired fd: ENODEV;
 * absent/evicted request: ENOENT; retained duplicate id: EEXIST.
 * Advertising/scan intervals, request_rx_duration, connection intervals and
 * event lengths use 125us slots; duration/supervision_timeout use 10ms;
 * conn_max_latency and max_events are counts. Address/type/frame/mode values are explicit
 * in profile, with no implicit mapping/default. Currently WS73_HCC only.
 * data/response are opaque complete profile data, not inner/outer AD builders.
 */
#define SLE_DISCOVERY_VERSION 1U
#define SLE_DISCOVERY_ADV_START 1U
#define SLE_DISCOVERY_ADV_STOP 2U
#define SLE_DISCOVERY_SCAN_START 3U
#define SLE_DISCOVERY_SCAN_STOP 4U
/* Explicit params -> successful OFF Complete; never enables advertising. */
#define SLE_DISCOVERY_ADV_CONFIGURE_OFF 5U
#define SLE_DISCOVERY_SCAN_INITIALIZE_OFF 6U
#define SLE_DISCOVERY_SCAN_RESPONSE 1U
#define SLE_DISCOVERY_FAULT 1U /* result flags, not Ready */
#define SLE_DISCOVERY_QUEUED 1U
#define SLE_DISCOVERY_PENDING 2U
#define SLE_DISCOVERY_SUCCEEDED 3U
#define SLE_DISCOVERY_FAILED 4U /* raw controller status preserved; error=0 */
#define SLE_DISCOVERY_CANCELLED 5U
#define SLE_DISCOVERY_FAULTED 6U /* error is negative errno */
#define SLE_DISCOVERY_RADIO_UNKNOWN 0U
#define SLE_DISCOVERY_RADIO_OFF 1U
#define SLE_DISCOVERY_RADIO_ON 2U
struct sle_discovery_adv_config {
	__u32 handle;
	__u32 mode;
	__u32 gt_role;
	__u32 interval_min;
	__u32 interval_max;
	__u32 channel_map;
	__u32 own_address_type;
	__u32 peer_address_type;
	__u8 own_address[6];
	__u8 peer_address[6];
	__u32 filter;
	__s32 tx_power;
	__u32 primary_frame;
	__u32 secondary_frame;
	__u32 secondary_phy;
	__u32 secondary_pilot;
	__u32 secondary_mcs;
	__u32 secondary_max_skip;
	__u32 sid;
	__u32 request_notification;
	__u32 max_requests;
	__u32 request_rx_duration;
	__u32 conn_interval_min;
	__u32 conn_interval_max;
	__u32 conn_max_latency;
	__u32 supervision_timeout;
	__u32 min_event_length;
	__u32 max_event_length;
};
struct sle_discovery_scan_config {
	__u32 own_address_type;
	__u32 filter;
	__u32 frame_types;
	__u32 active;
	__u32 interval;
	__u32 window;
	__u32 filter_duplicates;
};
struct sle_discovery_submit {
	__u32 version;
	__u32 profile;
	__u32 operation;
	__u32 flags;
	__aligned_u64 generation;
	__aligned_u64 request_id;
	struct sle_discovery_adv_config advertising;
	struct sle_discovery_scan_config scanning;
	__u32 handle;
	__u32 duration;
	__u32 max_events;
	__u32 data_len;
	__u32 scan_response_len;
	__u32 reserved;
	__u8 data[251];
	__u8 scan_response[251];
	__u8 reserved_tail[2];
};
struct sle_discovery_result {
	__aligned_u64 generation;
	__aligned_u64 request_id;
	__u32 version;
	__u32 flags;
	__u32 profile;
	__u32 operation;
	__u32 state;
	__s32 error;
	__s32 selected_power;
	__u32 radio_adv;
	__u32 radio_scan;
	__u16 dev_index;
	__u16 opcode;
	__u8 step;
	__u8 count;
	__u8 status;
	__u8 power_valid;
	__u8 reserved[4];
};

#define SL_IOCTL_CONTROLLER_EVENT_GET	_IOWR(SL_MAGIC, 0x87, struct sle_controller_event_query)

#define SL_IOCTL_DISCOVERY_SUBMIT _IOW(SL_MAGIC, 0x88, struct sle_discovery_submit)
#define SL_IOCTL_DISCOVERY_RESULT _IOWR(SL_MAGIC, 0x89, struct sle_discovery_result)


/* =========================================================================
 * Event type constants
 * =========================================================================
 */

#define SLE_MANAGEMENT_VERSION 1U
#define SLE_MANAGEMENT_MANAGED 1U
#define SLE_MANAGEMENT_DIAGNOSTIC 2U
#define SLE_MANAGEMENT_FREE 0U
#define SLE_MANAGEMENT_HELD 1U
#define SLE_MANAGEMENT_REVOKING 2U
#define SLE_MANAGEMENT_FAULTED 3U
struct sle_management_request {
    __aligned_u64 generation;
    __aligned_u64 lease;
    __u32 version;
    __u32 mode;
    __u32 flags;
    __u32 reserved;
};
struct sle_management_query {
    __aligned_u64 generation;
    __aligned_u64 lease;
    __u32 version;
    __u32 mode;
    __u32 state;
    __u32 flags; /* bit 0: owning file; bit 1: raw failure reply valid */
    __s32 error;
    __u32 status;
    __u32 opcode;
    __u32 reserved;
};
#define SL_IOCTL_MANAGEMENT_ACQUIRE _IOWR(SL_MAGIC, 0x8b, struct sle_management_request)
#define SL_IOCTL_MANAGEMENT_RELEASE _IOW(SL_MAGIC, 0x8c, struct sle_management_request)
#define SL_IOCTL_MANAGEMENT_QUERY _IOWR(SL_MAGIC, 0x8d, struct sle_management_query)

/* Independent privileged DLI seam trace, not a command/reply consumer. RX
 * denotes a validated HCC slot before DLI decoding; TX denotes transfer result,
 * timestamped after transport completion, so RX may precede TX in the log.
 * WS73 packet bytes include the A1/A2 header. Oversize packets have an explicit
 * truncated prefix and original_length, never silently masquerade as complete.
 */
#define SLE_SNOOP_VERSION 1U
#define SLE_SNOOP_PAYLOAD_MAX 320U
#define SLE_SNOOP_RX 1U
#define SLE_SNOOP_TX 2U
#define SLE_SNOOP_WS73_DLI 1U
#define SLE_SNOOP_STANDARD_DLI 2U
#define SLE_SNOOP_TRUNCATED 1U
/* Sensitive parameters omitted; original length retained, header only captured. */
#define SLE_SNOOP_REDACTED 2U
struct sle_snoop_record {
    __aligned_u64 seq, generation, timestamp_ns, lost;
    __u32 profile, original_length;
    __s32 status;
    __u16 dev_index;
    __u8 direction, format;
    __u16 captured_length, flags;
    __u32 reserved;
    __u8 payload[SLE_SNOOP_PAYLOAD_MAX];
};
struct sle_snoop_query {
    __aligned_u64 generation, after_seq;
    __u32 version, flags;
    __aligned_u64 reserved;
    struct sle_snoop_record record;
};
#define SL_IOCTL_SNOOP_GET _IOWR(SL_MAGIC, 0x8e, struct sle_snoop_query)

/* Owner-private result of a metadata diagnostic admitted by the same fd.
 * Input: version=1, flags=0, exact generation and nonzero admission seq.
 * State: 1 pending, 2 complete-success, 3 failed (error or controller status).
 * Missing/evicted is ENOENT; queries never acknowledge or remove a result.
 */
struct sle_diagnostic_result {
    __u32 version, flags;
    __aligned_u64 generation;
    __u32 seq, state;
    __s32 error;
    __u16 opcode;
    __u8 status, _pad;
    __u16 data_len;
    __u8 _reserved[6];
    __u8 data[64];
};
#define SL_IOCTL_DIAGNOSTIC_RESULT _IOWR(SL_MAGIC, 0xd0, struct sle_diagnostic_result)

/* Native profile1 metadata only. version1/flags0, exact selected generation,
 * nonzero request_id increasing for NEW admissions on this open fd; seq=0 on
 * input. Retry same retained ID/opcode/timeout returns the original seq and
 * deadline even after submission copyout EFAULT. Evicted old IDs ESTALE, changed
 * opcode/timeout EINVAL; never resend. A new fd is a new author/ID namespace.
 * action1 submits; action2 cancels only an existing request (same fields).
 * Cancellation snapshot is ECANCELED; on-wire slot/credits remain reserved for
 * real reply or timeout. Already-final requests keep their original result.
 * timeout_ms 1..5000 is the whole admission deadline, not wire-only time.
 */
struct sle_diagnostic_submit {
    __u32 version, flags;
    __aligned_u64 generation, request_id;
    __u32 timeout_ms;
    __u16 opcode, reserved;
    __u32 seq, action;
};
#define SL_IOCTL_DIAGNOSTIC_SUBMIT _IOWR(SL_MAGIC, 0xd1, struct sle_diagnostic_submit)

/* Unpublished experimental volatile address setup. CAP_NET_ADMIN and the
 * original File's exclusive Diagnostic lease;untouched Setup only,no links.
 * One mutation per registration. Six bytes in driver order,not an official
 * address allocation claim;no permanent storage operation is exposed.
 * version1/flags0/reserved0,nonzero generation/request_id,seq0 on input.
 * action1 admits;action2 withdraws original author with identical parameters.
 * Same ID/payload retry returns its original seq/deadline,never resends.
 * The existing Diagnostic result exposes the real setter Complete ONLY.
 * A causally newer real 0406 query must verify the value before the original
 * 1..5000ms deadline;until then metadata is invalid and Managed is refused.
 * Closing/releasing unverified setup quarantines instead of claiming Free.
 * This first version needs fresh initialization for a further address change.
 */
struct sle_runtime_address_submit {
    __u32 version, flags;
    __aligned_u64 generation, request_id;
    __u32 timeout_ms, seq, action;
    __u8 address[6], reserved[6];
};
#define SL_IOCTL_RUNTIME_ADDRESS_SUBMIT _IOWR(SL_MAGIC, 0xd7, struct sle_runtime_address_submit)


/* Unpublished Native typed connection ABI. File-local nonzero request IDs
 * increase monotonically. Submit has no copyout; retry/query never repeats I/O.
 * Cancellation cancels the author only, not the physical controller procedure.
 * Success requires real OUT, CommandStatus acceptance and matching outcome.
 * Timeout is an absolute whole-operation budget in milliseconds (1..10000).
 * Status validity is explicit, so raw status zero is not an absent result.
 */
#define SLE_CONNECTION_VERSION 1U
#define SLE_CONNECTION_CREATE 1U
#define SLE_CONNECTION_DISCONNECT 2U
#define SLE_CONNECTION_CANCEL_AUTHOR 3U
#define SLE_CONNECTION_QUEUED 1U
#define SLE_CONNECTION_ON_WIRE 2U
#define SLE_CONNECTION_AWAITING_OUTCOME 3U
#define SLE_CONNECTION_SUCCEEDED 4U
#define SLE_CONNECTION_FAILED 5U
#define SLE_CONNECTION_CANCELLED 6U
#define SLE_CONNECTION_FAULTED 7U
#define SLE_CONNECTION_COMMAND_STATUS_VALID 1U
#define SLE_CONNECTION_OUTCOME_STATUS_VALID 2U
#define SLE_CONNECTION_HANDLE_VALID 4U
struct sle_connection_parameters {
    __u32 filter, own_address_type, peer_address_type;
    __u8 peer_address[6], reserved[2];
    __u32 gt_negotiate, frame;
    __u32 scan_interval, scan_window, interval_min, interval_max;
    __u32 latency, supervision_timeout, event_min, event_max;
};
struct sle_connection_submit {
    __u32 version, profile, operation, flags;
    __aligned_u64 generation, request_id;
    __u32 timeout_ms, handle, reason, reserved;
    struct sle_connection_parameters parameters;
    __u32 reserved_tail;
    /* Unpublished v2: required for Disconnect, zero for Create/author cancel.
     * Kernel rechecks this physical reference at admission AND selection. */
    __aligned_u64 expected_lifetime;
    __u8 expected_address[6], expected_address_type, expected_role;
};
struct sle_connection_result {
    __u32 version, profile, state, operation;
    __aligned_u64 generation, request_id;
    __s32 error, fault_error;
    __u32 command_status, outcome_status, handle, flags;
    __u16 dev_index;
    __u8 reserved[6];
};
#define SL_IOCTL_CONNECTION_SUBMIT _IOW(SL_MAGIC, 0x9c, struct sle_connection_submit)
#define SL_IOCTL_CONNECTION_RESULT _IOWR(SL_MAGIC, 0x9d, struct sle_connection_result)

/* Observed physical links for one live registration. event_seq is sampled
 * atomically with the table; replay only link events newer than this barrier.
 * lifetime is registration-local and changes on handle reuse. flags=0 with
 * error means UNKNOWN, never an authoritative empty table. */
#define SLE_LINK_SNAPSHOT_MAX 16
#define SLE_LINK_SNAPSHOT_KNOWN 1
struct sle_link_info {
    __aligned_u64 lifetime;
    __u16 handle;
    __u8 role, address_type, address[6], reserved[6];
};
struct sle_link_snapshot {
    __aligned_u64 generation, event_seq, revision;
    __u32 version, profile, flags, count;
    __s32 error;
    __u16 dev_index;
    __u8 reserved[2];
    struct sle_link_info links[SLE_LINK_SNAPSHOT_MAX];
};
#define SL_IOCTL_LINK_SNAPSHOT _IOWR(SL_MAGIC, 0x9e, struct sle_link_snapshot)

/* Experimental manager-approved security mechanism; NOT authenticated Pair.
 * Both operations require the same active Managed File and CAP_NET_ADMIN.
 * flags selects exactly one mode1/2/3/4 below; no raw TX/RX/keys.
 * action1 arms T response; action2 starts G request. Other roles unsupported.
 * Once per physical lifetime; no same-life retry, no restart after expiry.
 * Entire original timeout1..5000ms includes policy admission/queue/replies.
 * state4 means only own real Complete plus observed peer capability bytes;
 * it is NOT an ACK that the peer processed our offer, pairing, trust or keys.
 * state8 is unauthenticated candidate key agreement after real peer proof;
 * all own relay Completes must drain. It does not grant trusted identity.
 * state3 is pending install; state9 requires real own command acceptance and
 * lifetime-bound0011 initial encryption-on, NOT Agent/identity/trusted Grant.
 * mode4 additionally requires the original author's explicit comparison-code
 * confirmation before DH proof. state11 reports this installed mechanism;
 * userspace Agent policy is separate from this historical result. Current
 * facts come from CONNECTION_SECURITY; fixed socket Grants freeze/check their
 * security epoch. Neither operation result nor Grant establishes Bond.
 * Legacy global security facade remains EOPNOTSUPP. Same-life re-pairing has
 * no qualified barrier and is rejected. Revoke/Down never refunds debt.
 */
#define SLE_SECURITY_CAPABILITY_ONLY 1U
/* Experimental no-entry/no-MITM/no-Bond candidate key agreement. state8 means
 * fresh peer DH proof plus drained real relay Completes, NOT authenticated
 * identity, installation, encryption, Agent consent or Bond. No raw keys/API.
 */
#define SLE_SECURITY_KEY_AGREEMENT_ONLY 2U
/* Explicit manager policy: no-MITM/no-Bond candidate then real role-specific
 * installation. state9 is observed UNAUTHENTICATED encryption, never Agent
 * approval, authenticated peer identity, trusted Grant or Bond. */
#define SLE_SECURITY_UNAUTHENTICATED_ENCRYPTION 3U
/* Explicit privileged numeric-comparison mechanism; Agent UI/policy belongs
 * to userspace, no Bond or arbitrary trusted flag.
 * flags8 marks a live comparison prompt; flags16 local confirmation,32 real
 * peer proof,64 installed numeric mechanism. state11 requires all actual
 * protocol/confirmation/installation stages, never an arbitrary trust flag. */
#define SLE_SECURITY_NUMERIC_COMPARISON 4U
struct sle_security_negotiation_submit {
    /* version2; absolute CLOCK_MONOTONIC ns, set before policy/Agent waiting.
     * timeout_ms bounds the remaining budget (1..5000), never resets it.
     * Session checks this original deadline through crypto and final submit.
     * Host coarse cleanup ticks do not extend authorization. */
    __aligned_u64 generation, lifetime, request_id, deadline_monotonic_ns;
    __u32 version, profile, action, flags, timeout_ms;
    __u16 handle;
    __u8 role, address_type, address[6], reserved[2];
};
/* Cancel only this original Managed File's security author request. Does not
 * release the controller lease, disconnect, clear installed keys or erase
 * submitted physical obligations. Successful ioctl is local withdrawal only;
 * terminal requests remain unchanged. No wire cancel/Complete is fabricated. */
struct sle_security_negotiation_cancel {
    __aligned_u64 generation, lifetime, request_id;
    __u32 version;
    __u16 handle, reserved;
};
struct sle_security_negotiation_result {
    __aligned_u64 generation, lifetime, request_id;
    __u32 version, profile, state;
    __s32 error;
    __u32 flags;
    __u16 handle;
    __u8 role, status;
    __u8 local_caps[10], peer_caps[10];
    __u32 comparison_code; /* valid only while flags8; may be zero (000000) */
};
/* Same original Managed File/request/physical identity; no raw proof or keys.
 * accept0 is local rejection, not a fabricated remote failure/physical rollback.
 * Reserved bytes zero; original deadline cannot be replaced or extended. */
struct sle_security_numeric_confirm {
    __aligned_u64 generation, lifetime, request_id;
    __u32 version, comparison_code;
    __u16 handle;
    __u8 accept, reserved[5];
};
#define SL_IOCTL_SECURITY_NUMERIC_CONFIRM _IOW(SL_MAGIC, 0xd5, struct sle_security_numeric_confirm)
#define SL_IOCTL_SECURITY_NEGOTIATION_SUBMIT _IOW(SL_MAGIC, 0xd2, struct sle_security_negotiation_submit)
#define SL_IOCTL_SECURITY_NEGOTIATION_RESULT _IOWR(SL_MAGIC, 0xd3, struct sle_security_negotiation_result)
#define SL_IOCTL_SECURITY_NEGOTIATION_CANCEL _IOW(SL_MAGIC, 0xd4, struct sle_security_negotiation_cancel)

/* Current physical Session mechanism snapshot; not an author-operation result.
 * Managed + CAP_NET_ADMIN, exact nonzero generation/lifetime, version1; all
 * output fields zero on input. No allocation, exchange, raw keys or trust bit.
 * security_epoch is per physical lifetime and advances at receipt ingress,
 * BEFORE ordinary event queueing. A lost/pending receipt cannot preserve an
 * older positive snapshot. Epoch0 is poisoned overflow and returns EOVERFLOW.
 * level0 none; level1 no-MITM encryption; level2 explicitly confirmed numeric
 * mechanism. These are NOT named peer identity, local app authorization, Bond
 * or a protected Grant. flags: cipher1, numeric confirmation2, proof4, accept8.
 * Query revalidates active lease, controller and physical lifetime under locks.
 * Off/failure/rekey/withdraw/Down/retire cannot revive with a late on event.
 * A snapshot is informational, not authorization for a later USB submission.
 * Firmware handle-only receipt attribution still needs a proven reuse barrier.
 */
struct sle_connection_security {
    __aligned_u64 generation, lifetime, security_epoch;
    __u32 version, profile, level, flags;
    __u16 handle;
    __u8 method, key_size;
    __s32 error;
};
#define SL_IOCTL_CONNECTION_SECURITY _IOWR(SL_MAGIC, 0xd6, struct sle_connection_security)

#endif /* _UAPI_LINUX_SPARKLINK_IOCTL_H */
