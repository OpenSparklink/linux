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
