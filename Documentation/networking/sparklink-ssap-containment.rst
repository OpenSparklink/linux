Historical SSAP containment stage
=================================

.. warning::

    Old SSAP business ioctls were subsequently deleted; their old numeric commands return ENOTTY rather than the containment-stage EOPNOTSUPP described below. The userspace Engine is not connected. No wire service or notification success is implied.

    Original source: e78b88f050aa98f7e8c83ff12c828eb172968d66. Historical evidence does not qualify the current image.

Legacy SSAP containment
=======================

The unpublished legacy remote SSAP ioctls return ``EOPNOTSUPP``. The offset-based
wire codec and unbounded read/write transaction engine were removed from
production; the codec remains only in ``selftests/sparklink/ssap`` as historical
test material. T/XS 20001-2025 table 32 defines permissions; tables 72, 75 and 76
use message-control fields for fragmentation and write commit/cancel. Checking
the old accumulator length would not make that codec standard-compatible.

Both legacy ingress paths reject the service-management channel without
parsing, credit/ACK side effects or draining another peer's notifications. The
unowned notification queue and duplicate drains are removed. Notification,
indication and method-without-callback operations explicitly return unsupported;
there is no default method echo. Local service staging remains for caller
migration, with atomic value replacement after allocation success and rejection
of oversized ioctl inputs instead of truncation. It does not publish a service.

The target Engine belongs to slkd; the kernel supplies complete connection PDU
channels, ordering, backpressure, disconnection and security context. Socket
ownership and budgets, standard codec/control flags, per-peer service and security
state, deadlines, cancellation, indication ACKs and real SSAP interoperability
are not implemented by this change. R04/R07/R08 and connection issues remain open.

The Native WS73 typed discovery path does not use this legacy Engine. Every new
kernel must still pass the real VM-only two-device discovery/recovery regression;
fixture success alone cannot qualify firmware, physical recovery or SSAP support.

Operation indicators
--------------------

The canonical UAPI names ``SL_SSAP_OP_*`` follow table 32: READ=1,
WRITE_NO_RSP=2, WRITE_WITH_RSP=4, NOTIFY=8, INDICATE=16 and BROADCAST=32;
descriptor write permissions occupy bits 8, 9 and 10. Bits 6, 7 and 11..31
are reserved and rejected before local database mutation. The legacy staging
byte cannot express descriptor permissions; callers must explicitly refuse that
narrowing rather than discard those bits. This is not the standard wire Engine
or an authorization decision: per-peer security and application policy remain
separate. Raw staging inputs also require zero reserved bytes and bounded values.
