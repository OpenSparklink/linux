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
The userspace SSAP Engine remains work in progress; old in-kernel SSAP service
logic was removed, not replaced by a qualified userspace Engine.

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

This is an incremental wakeup stage: the original 10 ms maintenance fallback
still runs. Separating original-deadline timers and removing periodic polling,
bounded continuous TX, no-lost-wakeup/drain interleaving validation and same
configuration real-device comparisons remain required. No latency improvement
or complete event-driven/performance qualification is claimed from source or
sequential dependency fixtures alone.

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
