SparkLink implementation roadmap
================================

This is an experimental implementation. Source coverage, a simulated test
result and physical controller acceptance are separate facts. The current
WS73 driver implements boot, native metadata queries, typed discovery and
per-controller Host readiness, as described in :doc:`ws73-development`. Basic
slkd/slctl discovery passes a synthetic USB integration gate; the physical
dual-controller milestone remains unverified.

The cross-repository roadmap is maintained in the userspace repository at
``docs/IMPLEMENTATION_PLAN.md``. Existing acceptance criteria remain in
`Linux issues <https://github.com/OpenSparklink/linux/issues>`_ and
`userspace issues <https://github.com/OpenSparklink/sparklink/issues>`_.
The Native WS73 tracker is
`Linux issue 8 <https://github.com/OpenSparklink/linux/issues/8>`_.
The full cross-repository plan is published in
`userspace issue 8 <https://github.com/OpenSparklink/sparklink/issues/8>`_.

First hardware milestone
------------------------

The first delivery target is an ordinary user selecting two physical WS73
adapters with slctl: one advertises a fresh random marker and the other
reports matching data, address and RSSI within ten seconds. Both must be
independently Ready after genuine controller queries. Twenty consecutive
rounds alternate roles; unplugging one must preserve the other runtime,
and replugging must work without restarting slkd. Applications run without
sudo. Reproducible runs retain actual receiver USB/HCC/DLI reports and
negative controls; virtual results cannot certify this over-air gate.

The implementation order is minimal per-device Runtime, WS73 boot/HCC/BSLE,
genuine DLI queries, advertising/scanning, kernel events, then dynamic
adapter/slctl routing. Four adapters in two concurrent pairs follow.
`Userspace issue 10 <https://github.com/OpenSparklink/sparklink/issues/10>`_
records this milestone. The complete roadmap and original issue criteria
remain; partial delivery does not close a whole issue.

Runtime migration status
------------------------

The uncommitted first stage gives each controller a fixed heap Runtime,
including pending/command queues, privacy state and event rings. Selection
no longer copies or swaps protocol fields. A two-model ReadMacAddr ownership
case passes, but the full 96-case guest suite reports three failed assertions
and the strict verdict is FAIL. This is development evidence, not RF acceptance.

The global SUBSYSTEM lock and a temporary Deref routing bridge still exist.
An explicit RuntimeContext now validates registration identity under each
ioctl helper lock; two concurrent processes each completed 10,000 matching
index/MAC queries. A later full run still failed its command completion
counter assertion, and a diagnostic run timed out in throughput testing.
Stable Arc fd bindings, independent runtime locks/workers, IRQ-safe RX ingress,
generation-tagged USB ingress and lifecycle cancellation remain required. Partial generation
validation does not certify removal/replug isolation. The detailed record is
in the userspace roadmap; original issue checklists remain open.

USB RX queue/wakeup references now use short IRQ-save raw spinlocks; RX
allocations use GFP_ATOMIC and allocation failures discard the whole payload.
The legacy workers have scheduling gates and a flush outside subsystem/IRQ locks on stop; these
remain global workers, and module teardown/RT/lockdep checks are not validated.
Image 16 builds, but the full 96-case suite still reports three failed
assertions. The ownership case passes in this run, while RX loss counters
also record dropped management completions. This is not a reliability gate.

Standards baseline
------------------

The local standards archive is ``../sparklink-standards``. The roadmap maps
its pinned versions and chapters to implementation and tests. DLI is
T/XS 10003-2025 V1.1.0; SSAP is in T/XS 20001-2025 V1.2.0; TCID and transport
modes are in T/XS 20002-2025 V1.1.2. SLE security is in T/XS 10002-2025
sections 9 and 13, with general security requirements in T/XS 40001-2022.
T/XS 20002 is not a security-management specification.

Peer-local TCID identity, basic-mode default SMTC, negotiated reliable SSAP
and the three separate fragmentation layers must remain explicit. The WS73
wire envelope does not redefine the standard TCID width or SSAP MTU.

The user-provided OpenHarmony ``communication_nearlink_service`` Host is
also a source reference, pinned to
``f0872dfaac33ffa99b80b352f6c05fba2df6414e``. The userspace document
``docs/NEARLINK_HOST_REFERENCE.md`` records the inspected modules and
differences. Its DLI opcode 0x0401 means SetEventMask, unlike the local
standard baseline, and its SSAP includes version 1.3 extensions. These
require explicit dialect/version selection rather than merging constants.
The real HAL depends on external HDI services; local-test stubs are separate
and cannot establish hardware acceptance. No reference build, differential
run or WS73 interoperability has been validated yet.

Ownership
---------

``net/sparklink`` owns the per-controller DLI Host, explicit dialect codecs,
command transactions, connection/TCID mechanisms, low-level fragmentation,
credits, security execution and atomic PHY configuration. A registered
Backend sends and receives complete wire packets, and owns its internal
channel and hardware lifecycle. It does not invent command completions or
implement SSAP and application policy.

``drivers/sparklink`` owns bus matching, firmware, USB/HCC/BSLE, queues,
power and recovery. ``slkd`` owns product enablement, D-Bus authorization,
pairing/trust policy, persistent credentials, SSAP Engine/Profile and PHY
policy. Closed vendor libraries, when available, run in a separate
``slk-vendord`` behind a versioned UserspaceProxyBackend channel.

Each controller owns its Backend reference, descriptor, Host, parser,
pending commands, generation, queues, workers, connections and security
state. The registry only indexes referenced objects. Atomic callbacks queue
bounded work; no global lock is held across I/O or synchronous cancellation.
Removal invalidates the generation, stops submission, drains work outside
registry locks and revokes the object after callbacks have stopped.

Implementation order
--------------------

1. Make test verdicts trustworthy, repair cross-language ABI drift and fix
   the userspace event wait while holding shared state. Freeze baseline
   revisions and protocol evidence.
2. Build the registered per-controller runtime, descriptor and lifecycle.
   Implement VirtualBackend, then migrate standard USB and split driver
   configuration from the protocol core.
3. Unify typed Host transactions, independent state/snoop subscriptions,
   management ownership and dynamic userspace controller objects.
4. Complete WS73 USB/HCC, BSLE/SLE readiness, Host dialect and real
   version/buffer, advertising, scanning and connection transactions.
5. Complete TCID/ACB/credit and the userspace-owned connection PDU channel;
   migrate SSAP Engine and Profile callbacks to userspace.
6. Complete security mechanism/policy, persistent Bond and PHY policy.
   Develop Proxy and the fake vendor adapter independently once the UAPI
   contract is established.
7. Run hotplug, mixed-backend, PM, diagnostic and compatibility gates;
   remove legacy ownership paths only after their replacements pass.

Evidence gates
--------------

Virtual, standard QEMU USB, fake vendor and real WS73 results are reported
separately. A requested but missing model must not silently fall back to a
passing non-USB run. Assertion failures, timeouts, missing expected cases and
kernel faults cannot be reported as PASS.

WS73 gates are boot (G0), SLE readiness and real DLI (G1), RF (G2), concurrent
data and userspace SSAP (G3), security and Bond reconnect (G4), isolation and
PM (G5), and mixed-backend/performance (G6). Use four devices as two pairs,
rotate initiator/acceptor roles and preserve one pair's traffic while the
other controller is removed or reset. Boot-to-runtime enumeration is only
G0, not proof of G1 or RF support.

Every run binds its result to source revisions and dirty diff hashes,
binary/config/tool/firmware hashes, selected devices, exact argv, inventory
and raw logs. Previously recorded runs without these hashes must not be
retroactively attributed to newly hashed artifacts. Update issues with
remaining criteria and evidence; close them only after all original
acceptance requirements are met.

Per-controller Runtime development evidence
------------------------------------------

The working tree now retains a stable Arc per registration. Each owner has
its own protocol mutex, IRQ-safe ingress ring and embedded RX/TX delayed
work. Bound-fd operations no longer rewrite the compatibility default route.
Registry lookup releases the metadata lock before protocol I/O. USB removal
quiesces the owner and drains work before freeing transport resources;
retained old fds cannot follow an index reused by a new registration.

A dedicated virtual lifecycle support gate is available from the source
root. It requires a built kernel, the custom usb-sle-dli QEMU and static
busybox; use a fresh output directory::

  python3 tools/testing/selftests/sparklink/run_runtime_lifecycle.py \
    --kernel-build /absolute/path/to/kernel-build \
    --qemu /absolute/path/to/qemu-system-x86_64 \
    --busybox /absolute/path/to/static-busybox \
    --output /absolute/path/to/new-run-directory

The gate checks explicit DLI queries, removal while another controller
remains usable, and old-fd invalidation across index reuse. It records QMP,
console, exact argv and source/binary/config hashes, including failed runs.
One virtual cycle passed on image #20; the full 96-case regression still
has nine failed assertions. This is not real WS73/RF, slkd dynamic-adapter,
unprivileged application, 20-cycle or complete lifecycle acceptance. USB
context generations, Host transactions/credits, connection handle mapping,
PM and the full fault matrix remain required.

Independent native WS73 snoop
----------------------------

SL_IOCTL_SNOOP_GET (0xc198538e) is a privileged passive observation channel,
separate from management leases and the consuming legacy raw reply queue.
Each Runtime has a 64-record preallocated IRQ-safe ring and waitqueue.
Readers explicitly select index and exact nonzero generation. They pass
version=1, after_seq and zero flags/reserved in a pointer-free 408-byte query;
the returned 376-byte record carries identity, sequence, CLOCK_BOOTTIME,
direction, transport status, original/captured length and up to 320 bytes.
The integer layout is eight-byte aligned; no compat user pointers exist.

CAP_NET_ADMIN is checked before usercopy and when polling a snoop fd.
PrivilegedObserve does not acquire a management lease, authorize a writer,
sync power or submit protocol work. Independent readers copy the same
retained records without consuming replies or other readers' records.
The kernel reports lost=seq-after_seq-1 after ring overwrite, and explicitly
marks oversized prefixes TRUNCATED. Payload tails and reserved fields are
zeroed. EFAULT does not acknowledge the unread record. An fd already in
controller-event mode rejects snoop with EBUSY and conversely; DEV_SELECT
resets observation mode. Ioctls on each open file are serialized.

Only WS73 profile 1 is implemented. RX records contain the service-10,
queue-8 HCC-validated SLE slot before DLI parsing. TX records contain the
A1 command bytes and submission/transfer result, timestamped after the
attempt returns; an RX response can precede TX_RESULT. Transport success
does not imply DLI Complete or radio delivery. This is a DLI seam trace,
not USB aggregate, HCC header, bootstrap, PCAP or physical RF capture.
Removal wakes stale observers with POLLERR|POLLHUP and ENODEV; reused
indices never retarget old fds. Producers do not allocate or perform I/O,
and release the IRQ retirement gate before sleeping fd mutexes or wakeup.

The daemon lifecycle runner's --snoop-tools option requires --radio-policy.
It runs actual slkmon/slkdump alongside managed slkd and ordinary slctl,
compares exported portable capture bytes, matches raw scan report data,
address and RSSI to the independent slctl result, exercises permission,
copyout retry, slow-reader loss, unplug wakeup and new-generation capture.
QMP, full console, capture files and source/input/binary hashes are retained.
These synthetic USB gates do not satisfy physical WS73/RF acceptance or
complete legacy-profile/Proxy/PDU/security/PM/release issue requirements.
