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

* `Target architecture <https://github.com/OpenSparklink/sparklink/blob/codex/sparklink-ws73/docs/ARCHITECTURE.md>`_
* `Execution plan <https://github.com/OpenSparklink/sparklink/blob/codex/sparklink-ws73/docs/IMPLEMENTATION_PLAN.md>`_
* `Current qualification and limitations <https://github.com/OpenSparklink/sparklink/blob/codex/sparklink-ws73/docs/CURRENT_CAPABILITIES.md>`_

Current interface boundaries
============================

``/dev/sparklink`` provides versioned Native management, diagnostic and complete
ControllerEvent queries. Channel sockets provide the current basic business
data path. Snoop is an independent privileged observation path. Legacy read(2)
event delivery, EVENT_COUNT/EVENT_STATS and raw DLI polling were removed.
Do not infer support from remaining legacy ioctl or Generic Netlink declarations.

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
