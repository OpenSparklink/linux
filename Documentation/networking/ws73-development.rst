WS73 development lab
====================

Use the physical host to compile and a single headless QEMU/KVM guest to run
the test kernel. Nested virtualization and a compilation VM are unnecessary.
All build artifacts live in an out-of-tree directory, ``../.dev/kernel`` by
default. The host kernel is not replaced and the driver is not loaded on it.

The experimental driver downloads boot firmware, then performs a per-device
vendor HCC/BSLE handshake and controller metadata queries in runtime mode.
Its current final state is ``native-runtime-setup``. This is not SparkLink
Ready: operational readiness policy and real RF validation remain required.
Versioned typed discovery submission is available for explicit per-fd testing;
legacy bare-enable/raw RF commands remain unsupported. Transport binding,
BSLE completion and wireless readiness are separate milestones.

Prerequisites
-------------

Install clang/LLVM, gcc, make, flex, bison, bc, cpio, ELF/OpenSSL development
headers, QEMU, Rust with matching rust-src, and bindgen-cli. The lab uses
the kernel's ``rustavailable`` check. Bindgen may be installed under the
workspace without system privileges::

  cargo install bindgen-cli --version 0.72.1 --locked --root ../.dev/tools

Compilation, packing the initramfs and running QEMU do not require sudo.
The user must have read/write access to ``/dev/kvm`` and the selected WS73 USB
nodes. A one-time administrator-installed udev rule may grant access to a
dedicated user group for USB devices ``ffff:3733``. The rule must also apply
after firmware re-enumeration. Do not grant access to the complete host USB
controller, which also carries keyboards and other devices.

Firmware
--------

The lab reads three original SDK files from ``../ws73_SDK/firmware/us``:
``ws73.bin``, ``wifi_cali.bin`` and ``btc_cali.bin``. Each contains a 64-byte
lowercase ASCII SHA-256 header followed by its image. All images are verified
before touching the device and packaged locally as
``/lib/firmware/sparklink/ws73/*.bin``. No firmware blob is added to the kernel
repository. Override the input with ``--firmware-dir`` when necessary.

Runtime mode additionally requires two board-approved raw files:
``bsle_custom.bin`` (140 bytes, the SDK's packed BSLE customization payload)
and ``pm_config.bin`` (4 bytes, little-endian platform PM configuration).
These files have no ASCII hash header. Supply them using
``pack --runtime-config-dir /path/to/board/config``; the pack manifest records
their exact bytes, sizes and hashes separately from the three boot images.
The driver logs their SHA-256 hashes before runtime I/O. Obtain the payloads
from the matching board/SDK configuration or an attributed vendor capture;
do not substitute zero-filled calibration or a configuration from another
board. No approved runtime configuration is currently present in this lab.
Omitting the directory still permits the explicitly limited USB boot gate;
runtime bring-up then fails with the missing-file error, without publishing
Ready. Files of the right size are not by themselves proof of correct RF
calibration or power policy.

Runtime sequence and tests
--------------------------

Each USB instance owns its buffers, TX sequence, worker and phase. The worker
validates both configuration files, waits up to 10 seconds for BSP_READY,
sends queue-9 PM configuration followed by queue-10 BSLE customization,
requires CUSTOMIZE_RECEIVED, sends the class SLE_OPEN message, and requires
BOOT_FINISH within its own 10-second deadline. DEVICE_ACTION_STATUS(SLE_OPEN)
alone does not finish boot. Panic, malformed aggregates, short writes,
transport errors and disconnect abort that instance; no fallback Ready is
published. The runtime receiver accepts the SDK's aggregate framing and
validates declared lengths and all slot boundaries before delivery. It never
searches slot padding for another frame and does not enable an undocumented
raw-netbuf fallback.

``runtime_transport`` is a read-only descriptor-validation flag, independent
of the handshake phase. The boot-only lab uses this flag to count bound
five-endpoint interfaces even if later BSLE bring-up fails. Inspect
``boot_stage``, ``boot_error`` and the complete kernel log separately; the
existing WS73_BOOT_GATE marker intentionally does not certify BSLE or RF.
Disconnect stops new I/O and joins bootstrap/fault work, the per-owner
protocol workers and both native RX URBs before releasing its retained
context. Automatic fault recovery and PM are not yet implemented.

The host test compiles the actual production wire codec and handshake
sequencer against synthetic I/O. It exercises padding duplicates, aggregate
truncation, a bad later slot, wrong acknowledgement order, action-only
completion, deadlines under continuous traffic, panic, send/open failure,
disconnect and a second independent instance. Run without USB access::

  gcc -std=gnu11 -O2 -Wall -Wextra -Werror \
    tools/testing/selftests/sparklink/ws73_bsle_test.c \
    drivers/sparklink/ws73/wire.c drivers/sparklink/ws73/bsle.c \
    -o /tmp/ws73_bsle_test
  /tmp/ws73_bsle_test

Use clang with ``-fsanitize=address,undefined`` for host memory checks. These
checks do not instrument the kernel or exercise physical URBs. The synthetic
payload in the tests is not a deployable customization file. The standard
DLI QEMU fixture has no WS73 HCC/BSLE endpoint model; a passing generic Runtime
test cannot certify this native handshake.

Native metadata queries
-----------------------

After fresh BSLE open, the same instance selects SLE queue 8 and queries
version (0x0404, five bytes), buffer capacities (0x0402, six bytes), the
80-bit feature map (0x0403, ten bytes), and public address (0x0406, explicit
address-type parameter 0, six bytes). This last command is specified by
T/XS 10003-2025 section 8.1.6; its availability on this WS73 firmware is
unverified. Failure never substitutes an assigned or cached address.
0x0401 is deliberately not sent as ReadCmdLen: the inspected WS73 dialect
assigns it to SetEventMask. No full command-length negotiation is claimed.

One initial probe slot is supplied only after fresh BSLE open. Later credit
values come from validated controller events and replace the previous value;
a zero window waits for a grant rather than inventing credit. Credit-only
opcode-zero events do not finish a query. A successful CmdStatus is acceptance
only; CmdComplete must match the outstanding opcode and exact return length.
Nonzero controller status is retained verbatim, including unknown values.
Malformed input, hardware error, panic, disconnect or a 10-second monotonic
deadline aborts the instance without retrying an uncertain transaction.

All metadata is validated in a temporary candidate and published only after
all four queries succeed. Buffer lengths/counts must be consistent, lengths
must fit the specified 11-bit capacity, and address cannot be all zero or
all FF. ``metadata_valid`` and ``controller_information`` expose
this immutable metadata. A successful query sequence now creates a pending
Rust ControllerRuntime after its two RX URBs open, but does not publish Ready.
``boot_stage`` and ``boot_error`` remain the bring-up observability interface.
Only native metadata queries are enabled; complete discovery transactions
remain the next protocol dependency.

The direct-production-code synthetic test covers independent instances,
zero/final-zero credit, unsolicited grants, wrong opcode, successful Status
before Complete, exact raw failure status, malformed/truncated or duplicate
reply, transport failure, disconnect, panic, invalid address/capacity and
late completion. It does not exercise USB endpoints or certify RF::

  gcc -std=gnu11 -O2 -Wall -Wextra -Werror \
    tools/testing/selftests/sparklink/ws73_dli_test.c \
    drivers/sparklink/ws73/wire.c drivers/sparklink/ws73/dli.c \
    -o /tmp/ws73_dli_test
  /tmp/ws73_dli_test

The user-space repository's ``tools/ws73-board-config.py`` exports explicit
SDK INI values to candidate payloads with a source/hash/provenance manifest.
Its default-SDK export is unverified board configuration, not approval to
apply that PM GPIO, power or calibration policy to these dongles. Preserve
that manifest with any eventual board-qualified hardware run.

Native Runtime and synthetic USB gate
-------------------------------------

The internal ``sparklink_native.h`` interface requires an explicit WS73 HCC
profile; unknown profiles fail instead of inheriting that dialect. It copies
driver operations and retains the context and module. Rust owns a WS73 Backend in each stable
ControllerRuntime, starts it with the actual post-bootstrap credit value,
and preserves the full five-byte version and ten-byte features. C/Rust layout
assertions bind the internal metadata layout. The legacy u32/u64 projections
are not complete version/feature representations. Connection count, MTU,
transport/measurement/security policy capabilities are not negotiated by
these four queries; the pending Backend does not substitute standard USB
capability defaults or implement those operations.

Registration starts as SETUP without UP/Ready and does not change another
controller's default selection. ``native_runtime`` exposes its id/generation,
streaming/fault state and unsupported-event counters. Bulk/notification URBs
carry the binding's immutable identity. RX callbacks validate the complete
HCC aggregate before passing SLE slots to the attributed owner. Native
management replies preserve exact opcode and status; successful Status does
not release the active slot before Complete. The driver validates metadata
and discovery successful Complete return lengths before invoking native
ingress; the generic core does not own a WS73 opcode/return-length table.
Oversized results fail instead of being truncated, and zero-credit
grants update the same bounded Host used by typed/raw requests. Unsupported
operations, including standard ReadCmdLen at WS73 opcode 0x0401, are rejected
before reserving pending state or credit. Domain/data decoding and full
native discovery transactions are still pending; unsupported well-formed
RX is counted rather than aliased to a standard event.

Command validation is owned by the retained driver's side-effect-free
``validate_command`` operation. The core calls it before allocating pending
state/credit and again before transfer. The WS73 implementation currently
allows only its four metadata queries. The fixed-size raw DLI ioctl rejects
a declared parameter length over 240 with EINVAL; it never silently clamps
the request to that buffer. This is an internal operations change, not a new
userspace ABI or an expansion of Ready capabilities.

The separate production ``discovery.c`` codec prepares the next native Host
step with an explicit WS73 schema: 49-byte advertising parameters, a
three-byte complete-data header (handle, operation, length), five-byte
advertising enable, eight-byte single-frame-type scanning parameters and
two-byte scanning enable. It never inserts defaults for power, addresses or
timing, and rejects unsupported multiple frame types rather than choosing
one. Advertising-parameter validation checks framing and the handle; the controller
must still reject unsupported values. The reference shares the data schema
with scan response, whose actual hardware behavior remains unverified here.

``ws73_discovery_adv_params`` now serializes every field of the 49-byte
configuration from a wide host-value structure. It bounds each numeric field
before writing any output, writes both intervals as little-endian 24-bit
values and all seven duration/connection fields as little-endian 16-bit
values, and copies both addresses exactly. Zero TX power stays zero;
``127`` is explicit no preference. Request notification/count (bytes 33/34)
are independent caller values, not a role-derived vendor default. This is
serialization, not controller capability or board/calibration validation.
Address types remain explicit WS73 bytes. ``ws73_discovery_ms_slots`` rejects
zero/overflow before converting milliseconds to 125-us slots: the largest
integral millisecond scan interval is 8191, and advertising interval is
2097151. It never narrows an overflowing interval.

``ws73_dli_validate_reply`` requires one exact A2 management event with
matching declared length. Opcode-zero credit events carry exactly three
parameters; Status carries exactly four, and acceptance is not Complete.
Known successful metadata replies have their exact query return sizes.
Successful advertising-parameter Complete carries one selected TX power
byte; data/scan-response/advertising-enable/scan-parameter/scan-enable
Complete carries no additional return data. Controller failure status and
its opaque data are retained; unknown successful return bodies do not add
command support. Runtime still rejects all discovery commands pending the
typed, stepwise Host transaction. No firmware is sent by these pure codecs.

The decoder for WS73 event 0x180b accepts exactly a 23-byte header plus its
declared 0..255 data bytes, preserves all header bytes and exposes raw signed
RSSI. Address type, direct address, PHY and the uninterpreted vendor byte at
offset 20 are retained. Short or trailing data fails without changing the
output; no normalization or truncation hides a malformed event. The decoder
now connected to the separate complete native event route described below.
The legacy command-slot limit and 240-byte raw event buffer are retained;
reports use the versioned route without being truncated. Native discovery commands still return
EOPNOTSUPP through Runtime, including syntactically correct commands.

``ws73_discovery_test`` checks independently specified marker/control/report
vectors, all complete-data/report lengths, unsupported frame sets, signed
RSSI values and unchanged outputs on failure. It also feeds the data codec
through production HCC command framing. Run it using the selftests Makefile
or compile its C source with ``discovery.c`` and ``wire.c``. These are
synthetic memory tests, not real dual-controller discovery or RF evidence.
The parameter tests include a distinct 49-byte golden vector, every field's
width/overflow boundary, every signed TX power byte, empty configurations,
all short output capacities, and exact scan timing conversion boundaries.
``ws73_dli_test`` additionally checks known Complete schemas, all 256 failure
statuses, credit-only/Status framing and unknown opaque return data.
The native lifecycle runner accepts ``--native-ws73-fault-mode short-reply``
or ``trailing-reply`` together with ``--native-ws73 --native-ws73-fault``:
these fixtures send valid HCC/DLI framing but a mismatched successful address
return length. The existing exact one-owner EPROTO withdrawal and surviving
owner queries are required in both modes; this is synthetic fault evidence.

Complete native controller event stream
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The WS73 driver now routes validated 0x180b bodies through the internal
``sparklink_native_event`` callback, independently of management reply slots.
The old 260-byte command-slot restriction does not apply to this route. RX
copies into 32 preallocated records under the attributed Runtime's IRQ-safe
lock; there is no per-report allocation or retained driver-buffer pointer.
The complete 23-byte vendor header and up to 255 data bytes are preserved.
Malformed report lengths fail before publication and withdraw only the
matching registration through the driver's existing fault work.

``SL_IOCTL_CONTROLLER_EVENT_GET`` (number 0x87, 360-byte query) exposes version
1 records with registration id/generation, profile, raw event code, receipt
``CLOCK_BOOTTIME`` timestamp, per-registration sequence and exact payload.
Records have 288 payload bytes and a fixed 336-byte layout; C/Rust size and
offset assertions include explicit eight-byte alignment for 64-bit fields.
The unused payload tail, flags and reserved fields are zero. This supplements
the old interfaces; it does not resize or reinterpret their records.

Each reader supplies ``after_seq`` and the exact generation. The initial
cursor may use generation/sequence zero. GET returns the oldest retained
newer record, and ``lost`` explicitly reports overwritten records since the
requested cursor. Readers do not compete for dequeue, and can replay retained
records. EAGAIN means no newer record; a future cursor/flags gives EINVAL,
unknown versions EOPNOTSUPP and a stale generation ENODEV. A failed copyout
does not acknowledge the record or advance poll readiness.

GET also selects native-stream poll readiness for that fd, including on
EAGAIN; legacy queue readiness is excluded in this mode. Waiters register on
this owner's PollCondVar and wake directly after publication. Retirement
wakes them with POLLHUP/POLLERR and subsequent GET returns ENODEV. DEV_SELECT
clears the subscription. Use an independently opened, selected fd for this
stream; management/control fds retain their existing behavior. A reused
device index cannot retarget a bound old fd or reuse its event sequence.

Currently this stream contains validated WS73 discovery reports only. It
does not claim complete native/standard snoop, command/event unification,
discovery reassembly, Ready, active scanning, or real RF reception. Native
discovery commands remain disabled until the full Host transactions exist.

Versioned typed operation submission and results
-----------------------------------------------

``SL_IOCTL_DISCOVERY_RESULT`` with version 1 and request_id/generation zero
probes the explicitly selected fd's current identity and last confirmed radio
command state. ``SL_IOCTL_DISCOVERY_SUBMIT`` requires that generation, profile
and a caller-chosen nonzero request_id. Its write-only ABI has no copyout after
admission: a user-memory fault cannot lose an accepted generated cookie. A
successful ioctl only accepts the complete plan, never confirms RF enabled.

The 704-byte submit contains all wide host parameters plus opaque complete
data and optional response. No defaults, AD formatting or implicit role/
address mappings are supplied. Reserved fields, unused configuration/data
bytes, lengths, profile, registration and operation shape are checked before
admission. Unsupported profiles reject support, not fall back to USB layouts.
Use the actual selected controller profile; encoding arbitrary reserved values
is not evidence of controller capability or board calibration.

Results are bounded to 64 per registration, queried non-destructively by
request_id/generation. Pending records never evict; the oldest terminal record
may evict (ENOENT). Retained duplicate ids return EEXIST, so callers must use
fresh ids while retained. Multiple readers and copyout failure cannot consume
results. Records contain queued/pending/succeeded/failed/cancelled/faulted,
matched step/opcode/count, original controller status, negative host errno and
actual selected TX power from the driver-annotated reply step. Successful
Status remains pending until matching Complete. Cancelled in-flight enable
completion marks radio state unknown until the physical stop completes.

Both radio domains begin unknown; issue and await explicit stops for both
before a start. Stop submission keeps the previous confirmed state; only
successful Complete confirms off. Failed stop preserves the previous state.
Start admission requires both domains confirmed off and no pending discovery
operation; stop can cancel a pending start. A transport/timeout fault cancels
remaining work, marks both radio states unknown and latches this owner's Host
fault without inventing credits. A replacement registration has fresh results,
identity and state; old fds/old generations never follow it. These radio fields
report confirmed command state, not PHY activity; autonomous termination and
full native capability/readiness policy still require integration.

The new standalone production result-store tests and the opt-in
``--native-ws73-discovery`` USB fixture gate verify native typed command groups,
optional response, delayed Status/Complete, errors at every step, failed stop,
cancellation, selected power, result EFAULT retry, fault isolation and replug.
Fixture reserved modes trigger synthetic errors/timeouts; never deploy these
vectors to a real controller. The fixture performs no firmware execution or RF
and cannot satisfy any real dual-device North Star criterion.

Driver-owned typed discovery preparation
----------------------------------------

The internal ``sparklink_discovery_request`` supplies complete advertising
or scanning configuration, data and an explicit optional scan response.
Preparation is an optional retained-driver callback, separate from raw DLI
validation. WS73 prepares bounded sequences of three/four advertising steps
(SetParam, SetData, optional ScanRsp, Enable), two scanning steps, or one
explicit stop. Every caller value survives; no role, power, address or board
default is inserted. A small scratch buffer preflights all steps before the
caller's output plan is changed. Inputs must be immutable and disjoint from
output. Unused bytes/steps are zeroed; invalid late data or enable fields leave
the previous output intact. This internal interface is not a userspace ABI.

The TX worker retains the Host recipe tag through Backend dispatch. A native
recipe is checked by the driver against its operation, position, count, wire
schema and enable value immediately before transfer. Missing typed callbacks
reject support. Raw commands still use the original metadata-only whitelist;
preparing a valid discovery frame never grants raw DLI permission. Core does
not contain WS73 opcode/parameter-layout tables. Preparing a plan performs no
I/O and does not establish capability, board calibration, Ready or RF success.

The versioned discovery submit/result API now invokes retained-driver
preparation and enqueues the native plan through the per-owner Host. Legacy
bare-enable and raw RF paths remain rejected. Native readiness/capability
policy, unsolicited termination tracking, dynamic adapters and slctl remain
pending; registrations continue to report SETUP, never a fabricated Ready.
Standalone selftests cover actual compiler output, whole-output preservation,
sequence-position/enable validation, and unchanged raw-command rejection;
they are synthetic, not native on-wire multi-step or real air evidence.

Typed command recipe foundation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The per-registration CommandHost now accepts a contiguous, preflighted
recipe of one to four typed commands. The preallocated 64-slot queue copies
all parameters (up to 255 internal bytes) before any transfer; invalid data
or insufficient capacity leaves the queue and current intent unchanged.
Each step carries the same non-wrapping cookie and absolute whole-recipe
deadline. Raw requests keep their independent pending sequence and FIFO
order. No allocation or transport I/O occurs under the Host's IRQ lock.

A successful Status can grant credit but does not release a recipe's
on-wire slot. Only opcode-matched Complete advances a step; a nonzero raw
status removes the remaining same-domain typed steps. Unrelated/raw work
is retained. New starts supersede older queued starts, while queued stops
remain physical barriers before a new start's configuration. An already
on-wire step keeps its reserved reply even if superseded, and its stale
reply cannot confirm a newer intent. Failure of an older stop barrier also
aborts a newer pending start. Timeout or uncertain transfer outcome latches
the existing owner Host fault without inventing credits. Only the final
successful Complete of the current enabling recipe confirms advertising
or scanning; intermediate parameter/data completions do not.

The existing standard USB typed advertising/scanning enables now use this
path as one-step recipes. The WS73 driver still accepts metadata only:
native parameter preparation, typed transport validation, complete native
recipes and their public operation-result API remain to be connected.
This foundation does not mark WS73 Ready or enable its radio. Stop's public
state/error reporting and native recovery still need the complete operation
integration; this is not all lifecycle/fault/PM acceptance.

``sparklink_host_plan_test`` compiles the exact production queue/progress
modules as a Rust test binary. It checks full-batch rejection, FIFO and
replacement across wraparound, every internal payload length, malformed
tags, every nonzero status at every step, Status acceptance, duplicate/stale
steps, cancellation, independent progress and preservation of stop barriers.
Build its selftests Makefile target with a host Rust compiler.

The lifecycle runner's ``--standard-host-recipes`` mode performs typed
start/stop advertising and scanning on both standard USB instances, each
followed by an independently tracked raw address query. The opt-in fixture
emits credit-bearing Status, delays Complete by 25 ms, and aborts if the
Host transmits another command before Complete is delivered. Both instances
must produce exactly two advertising and two scanning Completes, four
Statuses and four matching-address replies with no raw pending/timeouts;
the normal removal/replug generation checks still run. The verifier requires
complete early kernel logs and rejects missing, duplicate, malformed or
late recipe proofs. The frozen pre-change image #47 fails this gate at the
premature-command assertion, serving as a negative control. Multi-step
progress is tested in the production logic selftest; this USB gate exercises
one-step standard recipes, not native WS73 multi-step/RF/slctl acceptance.
The synthetic support gate adds forty maximum-length reports per owner to
exercise loss, independent fanout, poll, copyout retry and replug::

  python3 tools/testing/selftests/sparklink/run_runtime_lifecycle.py \
    --kernel-build /path/to/build --qemu /path/to/custom/qemu \
    --busybox /path/to/static/busybox --native-ws73 --native-ws73-events \
    --output /path/to/fresh-event-evidence

Context references outlive the Backend and all callbacks. Removal atomically
takes only the matching generation, keeps its registry index reserved while
workers/URBs drain, and invalidates old fds before reusing it. RX or uncertain
TX errors stop that instance and schedule process-context teardown; no
unregister or sleeping mutex runs in its USB IRQ callback. No reset/retry or
new credit is fabricated. A module-backed transport pins its module while
registered: unbind/unplug its interfaces before unloading. This is not a
completed module-unload/PM matrix.

The additional QEMU ``usb-ws73-test`` model is synthetic and runtime-only.
It has five vendor endpoints and acknowledges the production HCC/BSLE path,
then returns fake metadata and exact native management frames. Successful
Status precedes Complete by 25 ms; the model rejects a new command before
Complete is delivered. Complete advertises zero credit, followed by a real
fixture-generated opcode-zero grant. All addresses, firmware metadata,
configuration bytes and replies are test fixtures; no ROM download, firmware
execution, RF medium, daemon or ordinary-user application runs in this gate.

Build QEMU using ``qemu-sle-dli/build-qemu.sh`` and run::

  LIBRARY_PATH=/path/to/static/libc python3 \
    tools/testing/selftests/sparklink/run_runtime_lifecycle.py \
    --native-ws73 --kernel-build ../.dev/kernel \
    --qemu /path/to/qemu-system-x86_64 --busybox /path/to/static/busybox \
    --output /path/to/fresh-evidence-directory

Add ``--native-ws73-fault`` for one malformed aggregate on A. That run requires
only A to be removed with errno EPROTO, B to retain its generation and accept
queries, and remove/re-add to reject A's old fd and use a new generation.
The normal gate separately requires exact raw status 0xfe, both owners' 18
metadata queries, all 80 feature bits, all five version bytes, opcode-0x0401
rejection without changing pending statistics, and hotplug isolation.
Neither gate satisfies any real WS73/RF North Star criterion. Manifests record
synthetic configuration, initial input/source hashes and whether they remained
unchanged; any source or binary change during a run forces FAIL. Retain the
complete failures alongside successful retests.

Commands (from the kernel source directory)
------------------------------------------

Use a concrete rustc binary when the rustup default does not have rust-src::

  python3 tools/testing/selftests/sparklink/ws73-lab.py inventory
  python3 tools/testing/selftests/sparklink/ws73-lab.py configure --rustc /path/to/toolchain/bin/rustc
  python3 tools/testing/selftests/sparklink/ws73-lab.py build --rustc /path/to/toolchain/bin/rustc
  python3 tools/testing/selftests/sparklink/ws73-lab.py pack
  python3 tools/testing/selftests/sparklink/ws73-lab.py run --ports 1-2.1.1

Run the lab evidence unit tests without USB devices, KVM or a proprietary SDK::

  python3 tools/testing/selftests/sparklink/test_ws73_lab.py

The tests check artifact/config/manifest rejection, fixed mapping and failed
preflight records, strict gate results, lock contention and source hashes.
The pack test creates synthetic images with valid SDK-format hash headers,
packs and extracts them, then checks every recorded firmware hash and byte.
That test reports SKIP if gcc, ldd or cpio is missing; install the lab
prerequisites to exercise it. These tests do not establish a hardware gate.

``configure``, ``build``, ``pack`` and ``run`` acquire the same non-blocking
``../.dev/ws73-lab.lock``, including when different ``--build-dir`` values are
used. A second lab command fails rather than replacing artifacts or taking
the devices during an experiment. The lock file remains after exit; its
presence or saved PID alone does not imply a live owner. Only commands using
this runner share the lock, so other USB programs must be stopped separately.

``build`` records ``ws73-kernel-build.json`` and ``ws73-kernel.config`` in the
build directory. They bind the kernel hash and full configuration to the
actual make command, compiler versions, and source snapshots before and after
the build. A source change during compilation is explicitly recorded;
``source_unchanged=false`` cannot establish a single source snapshot for that
build. Git snapshots include the commit, tracked binary diff hash and hashes
of untracked files, including a new driver that is not committed yet.

``pack`` writes ``ws73-firmware-manifest.json`` beside the initramfs. For each
SDK input it records the absolute source path, complete file hash, payload
hash, SDK header, sizes and path inside the archive. The same record contains
the resulting initramfs hash and the init program/source/compiler identity.
The hashes describe the bytes actually packed. Changing the SDK afterward
does not change the archive; run ``pack`` again to use new images.

``run`` refuses missing or unsupported manifests, kernel/initramfs hash
mismatches, and a configuration that differs from the recorded build. Older
artifacts made before these records existed require ``build`` and ``pack``
again. The runner does not backfill old run logs with current SDK or source
hashes. It records the current source separately from the recorded kernel
build source, so testing an older artifact does not claim to test the current
checkout. Commit or retain the actual dirty changes when sharing a run;
hashes identify those changes but do not reconstruct them.

The run command requires explicitly selected physical USB paths and verifies
that they are WS73 devices, writable and not already bound to a host driver.
It does not detach host drivers. The physical path survives changes in USB
device address during boot firmware download. ``--ports`` can select up to
four devices, for example ``1-2.1.1 1-2.1.2``. Discover paths again after
moving a hub or changing the machine.

The runner watches address changes at the selected physical ports and uses
QMP to detach the stale guest USB device and reconnect the new enumeration.
This handles boot-to-runtime changes even when QEMU's automatic reconnect
does not propagate the change. Reattachments are recorded in ``reattach.json``.
QMP traffic is saved in ``qmp.jsonl``. Devices are introduced one at a time
after the preceding runtime interface binds, then retained together for the
final gate. This avoids reconnecting one USB device while QEMU is forwarding
another boot download. It is not a concurrent-firmware-upload test. Guest USB
resets are disabled; QEMU may still reset a physical device on process exit.

Each run prints its ``manifest.json`` path in a unique, UTC-timestamped build
subdirectory, including failures during preflight. The record contains:

* kernel/initramfs hashes, a full ``kernel.config`` snapshot and copies of
  the build and firmware manifests;
* source revisions and dirty hashes, runner and QEMU binary hashes, build
  tool versions and versions observed at run time;
* fixed physical-port to guest-device/port mapping, expected device count,
  exact QEMU argv, and the explicitly limited gate scope;
* ``inventory-before.json`` and ``inventory-after.json``, serial console,
  QMP traffic and reattachment records when the VM was started;
* final PASS/FAIL, failure phase/reason, process result and parsed guest
  markers. A still-RUNNING manifest is incomplete evidence.

The final gate requires exactly one matching PASS marker for the requested
device count, a successful QEMU exit, no kernel panic/warning/sanitizer
diagnostic, and unchanged artifacts. Boot mode does not yet assign a ready
SparkLink controller id or generation; the manifest leaves those fields
unknown. The guest has no network, shared host filesystem or persistent disk.
Firmware runs in device RAM and may remain running after the guest exits;
unplug/replug to repeat a cold boot.

``WS73_BOOT_GATE: PASS`` only means the requested number of runtime USB
interfaces were bound. It does not prove a fresh download if a device was
already running, and does not prove SLE readiness, DLI transactions, pairing
or RF traffic. Use the download messages and the pre-run inventory to confirm
the boot-to-runtime path. The initial implementation has no runtime PM or
automatic firmware retry; failures expose ``boot_error`` on the interface.

Controller snapshot and dynamic daemon (partial North Star work)
---------------------------------------------------------------

``CONTROLLER_SNAPSHOT`` (0x8a, 64 bytes, version 1) requires DEV_SELECT
on the calling fd. generation zero probes that registration; a nonzero value
must match. Input flags and reserved bytes must be zero. Returned fields
include registration generation/index, bus/profile, current Host command
credits, five version bytes, ten feature bytes, address and buffer capacities.
``FULL_METADATA`` identifies the actual native query tuple; the legacy profile
returns projected metadata and never sets that validity bit.

Native Setup becomes Ready only after successful advertising-stop and scan-stop
Complete events confirm initial off states. A failed Status does not establish
Ready. Ready persists during subsequent radio operations: it describes Host
usability, not RF activity, board qualification or calibration validity. A
latched Host fault clears Ready and returns Fault plus the negative errno.
Unplug invalidates selected fds and generation-specific queries with ENODEV.
The registration/debugfs transport SETUP flag remains a bootstrap-stage marker;
the new snapshot is the authority for Host readiness.

slkd now enumerates the allocated-device mask, independently selects each
registration for control and event fds, and publishes generation-specific paths
``/org/sparklink/slk<ID>_g<GENERATION>``. It can start with no controllers and
remove/recreate adapters without restarting. Native initialization submits the
two typed stops and waits for their matching result records without holding
business-state or directory locks. Native event subscriptions preserve complete
WS73 report headers/data and explicit loss independently of the legacy ring.
Native SSAP profiles remain unsupported. Basic native scan/advertisement policy
is now supplied by userspace; Host Ready alone cannot certify its RF behavior.

The reproducible software integration gate is::

  python3 tools/testing/selftests/sparklink/run_daemon_lifecycle.py \
    --kernel-build <build-dir> --qemu <model-enabled-qemu> \
    --busybox <static-busybox> --userspace <sparklink-checkout> \
    --dbus-daemon <dbus-daemon> --output <new-evidence-directory>

It runs actual slkd/slctl binaries as guest uid 1000 against synthetic WS73 USB
controllers, verifies independent Ready, survivor identity, rejected stale
selection, new generation and the same daemon process after hotplug, and saves
source/image/program hashes, QMP traffic and complete kernel logs. It is not
real WS73 firmware execution or RF/no-sudo acceptance on the user's machine.
The original North Star criteria and full S0--S6 issues remain open.

Basic policy and synthetic CLI discovery
----------------------------------------

Add ``--radio-policy`` to the daemon lifecycle command above to exercise actual
uid-1000 slkd/slctl advertisement, scanning and stops through the typed native
API. Policy-enabled test controllers in an explicit nonzero ``runtime-medium``
group can report another live controller's advertisement, never their own data.
Both properties are opt-in and disabled in the existing native transaction gate.
The 20 alternating rounds and two rounds after hotplug retain fresh random
markers, exact data/address/RSSI, kernel receipt times and matched results; each
phase also observes no new reports for two seconds with transmitters stopped.
The verifier rejects wrong addresses/generations, stale sequences, timeouts,
loss, failed/missing/duplicate completions and misplaced lifecycle evidence.

This model is an explicit synthetic medium, not an RF recording. Production
policy does not reside in the model: libsparklink supplies full typed requests,
the driver independently validates/encodes them, and actual firmware status
remains authoritative. The real North Star and four-controller parallel pairs
still require physical devices, qualified configuration and receiver USB/HCC/DLI
captures. Native event fds activate their subscription before epoll registration
so the selected controller's queue can wake the daemon.

Matched Complete timing
-----------------------

``SL_IOCTL_DISCOVERY_TIMING`` (0x8f, 48-byte ``sle_discovery_timing``)
observes an explicit selected generation/request without taking management
ownership or consuming events. Version 1, flags/reserved zero and nonzero
identity are required. Missing requests return ENOENT; stale generations
return ENODEV. The existing 64-byte discovery result and its ioctl are unchanged.

The Host stamps CLOCK_BOOTTIME when an opcode-matched response enters its
reserved slot, before worker consumption. Only the final successful Complete
of the current public recipe publishes that timestamp. Pending, failed,
cancelled and faulted recipes without success retain zero; later replies/faults
never rewrite a previously completed result. This clock denotes validated DLI
Complete receipt, not a PHY start timestamp. Readers cannot generate success.

Ordinary applications obtain ``GetDiscoveryTiming`` via slkd. slctl bounds
matching RX and observation to ten seconds after this receipt and keeps an
independent invocation lower bound against older queued RX. Query delays count
against the window. No fallback to daemon poll time or a narrower admission
window is permitted. The explicit model tests remain software support only;
physical firmware/RF and all real North Star checks require hardware evidence.

WS73 blocking OUT and early replies
----------------------------------

The native TX worker acquires a separate reference to the copied C transport
under its owner's protocol mutex, then releases that mutex before validation
and blocking USB OUT. The transport context and module reference remain alive
until the last reference drops. Invalidation stops admission and joins the TX
worker before closing the Backend; the retained handle never looks up a reused
controller index. The standard USB and legacy Backend paths still have separate
lock migration work and are not covered by this native-only change.

The command Host can receive a Complete before USB OUT returns. It retains that
reply and its original CLOCK_BOOTTIME, but releases neither the active slot nor
the terminal result until successful transport completion with the matching
cookie. An early reply does not disable the command deadline. Failed OUT or
invalidation discards a pending reply; a late transport notification cannot
revive a faulted Host. Acceptance Status and credit grants remain observable
without resolving the command.

Build the custom QEMU from the current model and run the following independent
synthetic gate with a fresh output directory::

  python3 tools/testing/selftests/sparklink/run_runtime_lifecycle.py \
    --kernel-build /absolute/path/to/kernel-build \
    --qemu /absolute/path/to/qemu-system-x86_64 \
    --busybox /absolute/path/to/static-busybox \
    --output /absolute/path/to/new-run-directory \
    --native-ws73 --native-ws73-tx-barrier

Only the first post-bootstrap ReadLocalFeatures OUT is deferred for two seconds.
The host observes both a held OUT and the Complete delivered through IN before
signalling the guest on a separate UART. The guest requires its own snapshot
within 200 ms, an unaffected owner's actual DLI query, exactly one acceptance
Status, an unresolved query throughout a 100 ms observation, and the final
correct feature reply after OUT success. The full existing remove/re-add gate
then runs. QMP, actual model OUT/IN order, latency, complete kernel log and
source/input hashes are retained. The fixture's initial native registration is
SETUP; this race gate requires its state to remain unchanged, not native Ready.

Local kernel #71 passes with a 0.004 ms snapshot; exact old kernel #69 blocks
for about 1.97 seconds and fails the same gate. Nine standard/native lifecycle,
recipe, malformed reply, event, discovery and ownership gates pass. The original
three-controller 96-case suite passes with 1056 OK, no FAIL/SKIP and three
existing WARN. The companion ordinary-user synthetic 20+2 discovery rounds,
TX-off controls and hotplug run also pass; these are not physical WS73 evidence.

Kernel build commands must select a toolchain with matching rust-src explicitly
(``ws73-lab.py --rustc /absolute/toolchain/bin/rustc``). A stable proxy without
rust-src caused the first local build to remove Rust/SparkLink configuration;
the pre-boot gate rejected that image. The rejected build and initial test
failures remain alongside the qualified fixed-toolchain run. Evidence is frozen
locally in ``.dev/tx-unlock-final-evidence.json``; all real North Star checks and
the remaining full issue requirements stay open.

Early Complete followed by terminal OUT failure
----------------------------------------------

The same pending-reply barrier now supports three independent production-driver
tests. Use the command above with ``--native-ws73-tx-terminal out-error``,
``short-out`` or ``unplug`` instead of ``--native-ws73-tx-barrier``.
The synthetic fixture first delivers a successful Complete on IN while holding
the corresponding OUT. It subsequently returns STALL, completes OUT one byte
short, or has its still-pending packet cancelled by model removal. These are
USB transport tests, not real unplug or RF acceptance.

The guest verifies acceptance without query resolution before the terminal
event. It polls for retirement while rejecting a successful feature reply,
requires only the affected owner to disappear within four seconds, and checks
that its raw result/admission/snapshot fds return ENODEV and its retained event
subscription signals HUP. STALL and short completion preserve EPIPE and
EREMOTEIO respectively in the driver's failed state; two observations bracket
the survivor's 18-query exercise. The unplug runner also confirms via QMP that
OUT is still pending immediately before deletion, and requires the actual
model's cancellation marker rather than an eventual success marker.

Replacement uses a new generation and address. Both old fds remain retained
while the guest observes at least 2200 ms of monotonic time, crossing the
cancelled packet's original deadline. Old descriptors still cannot submit,
read results or obtain a snapshot; new feature replies belong to the new
registration and the survivor's identity stays unchanged. The verifier checks
the measured duration, actual model outcome, phase order, complete kernel log,
exit status, and exact generation/driver-error evidence together.

All three final tests pass on the existing kernel #71. Measured retirement
after the pending barrier was 1849.309 ms (STALL), 1847.687 ms (short OUT), and
26.692 ms (unplug). The exact same compiled unplug test fails on #69 at a
1967.032 ms blocked snapshot. Nine new verifier unit cases bring the kernel
harness to 259; the success race and existing native discovery/event/ownership
gates also pass. The new QEMU's original 96 cases pass with 1058 OK, no FAIL/SKIP
and the three existing WARN. The ordinary-user synthetic 20+2 round control,
TX-off, hotplug, capture and binding gates pass on the same new QEMU. Kernel
runtime sources and the compiled Rust companion are unchanged in this batch.

Current sources, actual fixture/object/QEMU/kernel/guest/capture hashes,
old-kernel counterexample and first versus strengthened measurements are frozen
locally in ``.dev/tx-terminal-final-evidence.json``. Physical entry still lacks
WS73 hardware; real North Star acceptance stays 0/7 and board qualification
NOT_ASSERTED. Native/legacy lock migration, real hardware, four parallel
devices and the remaining full S0-S6 issue requirements remain open.

Native open without the protocol state mutex
-------------------------------------------

Native registration now retains its transport, releases Runtime state, and
opens under a separate per-owner lifecycle mutex. Read-only snapshots remain
available in SETUP. Management acquisition returns EAGAIN until open succeeds;
neither a rejected lease nor an unowned raw command advances admission. This
transport-open condition does not itself mark a controller Ready.

Retirement closes admission before joining open. A successful late open is
adopted only for teardown and closed exactly once; it cannot start new work.
An unsuccessful open must clean up its own partial resources. Failed
registration cleanup checks the original generation and cannot unregister a
replacement. Ingress is published before RX starts and is unpublished after
the lifecycle join; native worker startup does not republish the owner.
Native callbacks must queue unregister on another process-context worker,
not invoke it synchronously from open, close, send or an IRQ callback.

The guest-only ``native-open`` external module blocks a native API callback
until the C test releases it. It has no USB, firmware or RF implementation.
The four cases are success, EIO, retirement during successful open and
retirement during failed open. Each checks a responsive full SETUP snapshot,
ten EAGAIN lease attempts, no unowned send, exact get/put/close counts, and an
actual synthetic WS73 survivor query before and after release. Retiring open
must keep its index reserved; retained old descriptors and stale unregister
identities are checked again while later registrations reuse that index.
The test also requires a clean fixture module unload and full kernel log.

Run with an already compiled matching kernel build tree (for Module.symvers
and generated headers), a frozen image/config manifest, test QEMU and BusyBox::

  python3 tools/testing/selftests/sparklink/run_native_open_test.py \
    --kernel-build /absolute/frozen-image \
    --module-build /absolute/kernel-build \
    --qemu /absolute/qemu-system-x86_64 \
    --busybox /absolute/busybox --output /absolute/new-test-output

The fixture is loaded only inside that guest. Historical comparison needs a
module compiled for the old kernel's release; do not force-load a mismatched
module. The final guest executable and fixture C object are byte-identical in
the #71 comparison; module release metadata differs. The old snapshot waits
10065.533 ms and fails; final #74 snapshots take 0.002/0.001/0.001/0.002 ms.
Eight new fail-closed verifier cases bring the kernel harness to 267. The
fixture and twelve transport/lifecycle regression gates pass, including three
OUT terminal failures, successful OUT, discovery, events, management, three
protocol faults and the standard USB lifecycle/recipes. Original 96 cases
pass with 1058 OK, no FAIL/SKIP and the three existing WARN. The #74 ordinary
user slctl support run passes 20 alternating plus two recovery rounds under
the same daemon, TX-off, survivor, capture and C/Python binding gates.

Final source/input/kernel/module/guest hashes and the counterexample are
recorded locally in ``.dev/native-open-final-evidence.json``. Earlier #73 runs,
the verifier/guest build corrections and the mismatched-module comparison
are retained separately. Companion Rust sources and executable hashes are
unchanged; no new Rust tests/clippy, remote CI or 32-bit runtime is claimed.
Native open is covered here; broader legacy blocking-I/O migration and the
complete lifecycle/recovery issue are still open. Physical WS73/RF acceptance
remains 0/7, board qualification NOT_ASSERTED, and four devices/two parallel
pairs remain subsequent work within the retained full S0-S6 scope.
