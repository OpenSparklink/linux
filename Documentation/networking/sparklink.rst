.. SPDX-License-Identifier: GPL-2.0

=========================
Linux SparkLink subsystem
=========================

This is an experimental, unpublished Linux subsystem. Source availability,
offline tests, bounded proofs and physical-device qualification are separate
facts. The complete protocol stack is not implemented in the kernel.

Ownership and authoritative documents
=====================================

The target separates device drivers and per-controller Native Host Runtime
from userspace policy, SSAP and Profiles. Kernel mechanisms own generation,
connection lifetime, CMTC/DTAP, bounded credit accounting and channel sockets.
The userspace SSAP Engine uses the shared channel path; old in-kernel SSAP
service logic was removed. Consult the qualification entry for the exact
implemented, offline-tested and real-device scopes; a source module is not
a claim of complete SSAP, security or Profile qualification.

The following user repository documents are the single authoritative entries:

* `Target architecture <https://github.com/OpenSparklink/sparklink/blob/codex/sparklink-ws73/project/architecture.md>`_
* `Execution plan <https://github.com/OpenSparklink/sparklink/blob/codex/sparklink-ws73/project/implementation-plan.md>`_
* `Current qualification and limitations <https://github.com/OpenSparklink/sparklink/blob/codex/sparklink-ws73/project/current-capabilities.md>`_

Current interface boundaries
============================

``/dev/sparklink`` provides versioned Native management, diagnostic and complete
ControllerEvent queries. Channel sockets provide the current basic business
data path. Snoop is an independent privileged observation path. Legacy read(2)
event delivery, EVENT_COUNT/EVENT_STATS and raw DLI polling were removed.
Do not infer support from remaining legacy ioctl or Generic Netlink declarations.

Managed connection observations
===============================

The unpublished LINK_QUERY_SUBMIT/RESULT operations provide typed ReadRSSI and
ReadPHY for Native profile 1. The original File must hold the Managed lease;
submission captures its epoch and full connection lifetime, handle, role and
peer identity. Both operations require CAP_NET_ADMIN. Results are nonconsuming
author history and remain readable after lease release on the same live Runtime.
They cannot be obtained through a second Diagnostic lease or raw opcode path.

Queue selection and the final atomic USB command ticket recheck the captured
identity, lease and original deadline. Successful Status is acceptance only.
A successful Complete must contain the full reply and matching handle. Release
cancels pending authors without erasing the retained physical reply slot or
returning uncertain credit. The existing command ledger and bounded queue own
all results, not a new connection procedure or Host.

Result flags distinguish current identity at the locked snapshot, available
value, and genuine controller status. Current identity is not sample freshness
or permission to submit later. RSSI 127 is invalid. PHY carries eight wire fields;
SDK dialect interpretation, actual firmware acceptance and RF behavior need
separate evidence. Command completion is not peer application delivery.
The wire reply has no generation/lifetime token: correct controller reply
ordering and the existing quarantine/reinitialization barriers remain explicit
hardware assumptions, not proven by handle equality or pure-source tests.

The basic channel capability exchange keeps the SDU MTU and the complete DTAP
PDU MPS separate. The current Native implementation advertises MTU 2042 and
MPS 2047; these are local implementation limits, not universal protocol maxima.
The selected capability-response PDU needs MPS at least 20. A smaller peer MPS
reduces socket admission by the complete basic header: five bytes for CUTC,
four for SMTC. CHANNEL_INFO reports the resulting SDU budget and PDU budget
separately. Oversize sends fail with EMSGSIZE; oversize RX is dropped. ACB
fragment size and controller packet credit are independent of both budgets.
Source tests and bounded checks do not establish firmware or peer acceptance;
consult the qualification entry for the exact image and remaining gates.

Dynamic basic channel setup is an unpublished version3 socket address extension
(64 bytes). CAP_NET_ADMIN plus the current Managed epoch is required to stage
it: bind registers a passive, port/AID-scoped per-connection endpoint;
nonblocking connect returns EINPROGRESS for an active request. Neither action
publishes a final data Grant. CHANNEL_INFO remains EAGAIN and POLLOUT remains
clear until the real CMTC exchange and Runtime identity revalidation complete.
Local and remote TCIDs are assigned separately in 0x80..0xdf. PI is restricted
to the user-defined range 241..250. Port/AID matching is not authentication.

There are four dynamic slots per physical connection lifetime. Slots, TCIDs and
outbound signaling identifiers are not reused within that lifetime; terminal
entries remain bounded tombstones. This is a resource limit, not a proof of
safe arbitrary TCID reuse. Basic mode is the only supported mode; a preferred
SLQI does not promise a programmed QoS policy. Final fd release cancels an
unsubmitted setup, retains an already-submitted physical obligation and drives
actual CMTC cleanup. A peer logical close forbids new TX/RX, while complete RX
queued before that close may drain under the original Runtime authorization.
Managed revocation and physical disconnect retain their existing failure
semantics and cannot renew an old fd. Reliable/security-protected modes and
blocking channel setup are explicitly unsupported.

Session event wakeup staging
===========================

Software TX admission, initial binding and final channel release now request
immediate execution of the existing unique Session worker. Native ACB ingress
and actual NOCP accounting publish a coalesced per-controller hint, then wake
the Runtime worker; it takes Session references in process context and notifies
them outside table/Host/data/gate locks. USB callbacks do not take the Session
table mutex or execute sleeping channel work. A notification grants neither
credit, Ready, authorization nor physical delivery.

The Session lock serializes enqueue with stop's close-before-cancel/join. A
new queue, including a requeue while running, retains one reference; modifying
an already pending queue keeps its existing reference. Closed Sessions reject
further enqueue. Actual submit still revalidates Grant, generation, lifetime
and Ticket. The atomic hint is not a replacement for these locked states.

The unique worker now selects the earliest original negotiation, dynamic
channel, queued/begun PDU or pending control-response deadline. An idle open
Session does not queue maintenance work. A pass drains at most 16 RX PDUs. TX
uses an eight-attempt, 4096-byte, two-millisecond admission quantum and rotates
the six channel slots at PDU boundaries; a begun PB sequence retains the physical
connection. The time budget limits the next attempt, not the duration of an
already started synchronous transport call. Residual runnable progress requests
another immediate pass. Queue admission and real RX/NOCP notifications remain
the only normal readiness sources.

Only an actual data-credit reserve failure marks the internal CREDIT wait.
An unsubmitted PDU keeps its channel's service turn across that wait: an
empty-pool probe has not served a PDU. Otherwise a long channel can repeatedly
win newly returned credit before the already selected short channel. A begun
PB stream remains uninterrupted, and queued deadlines and author withdrawal
are still checked before the next actual submission.
Other EAGAIN results retain a finite 10 ms retry bounded by the operation's
original deadline. USB success does not return credit, and an uncertain USB
failure cannot be classified as an empty pool or refund debt. Runtime's separate
command/lifecycle scheduling is unchanged. Expired unsubmitted queues and
negative responses cannot hide behind another begun PDU and create a zero-delay
loop. Dropping them does not settle the begun PDU's physical obligations.

Source, sequential dependency fixtures and bounded helper checks do not grant
new real-device, concurrency or performance qualification. Actual callback/
queue/drain interleavings, starvation/load and same-configuration device
comparisons still require the separately recorded gates.

The existing Session TX trace records dynamic CMTC connect, response and close
attempts in the same control-observation namespace as other CMTC sends. Begin,
actual Runtime-ticket consent and joined return are separate stages. A failed
consent is not successful USB acceptance, and USB acceptance is not controller
completion or peer delivery. Trace-only sequence numbers do not replace wire
identifiers, deadlines, Grant or credit. Missing dynamic-control observations
must fail the complete trace/USB join rather than silently excluding packets.

UAPI has not been published: callers, Rust/C/Python bindings and tests may be
migrated together without an old ABI compatibility period. Match actual headers
and source revisions; reserved-field checks and errors vary by request and must
be verified rather than assumed for every structure.

Development and qualification
=============================

Driver and physical WS73 tests are VM-only. Documentation builds must not load
firmware, install services or issue device commands. Each physical report must
identify its kernel/service/runner source, input hashes, scope and failures.
Historical PASS never qualifies a later image. Artificial failures, QMP, hub
power cycling and manual unplug do not establish natural automatic recovery.

The previous overview is retained at `its original revision
<https://github.com/OpenSparklink/linux/blob/e78b88f050aa98f7e8c83ff12c828eb172968d66/Documentation/networking/sparklink.rst>`_.
It includes retired interfaces and is not a current installation guide.
