WS73 development lab
====================

Use the physical host to compile and a single headless QEMU/KVM guest to run
the test kernel. Nested virtualization and a compilation VM are unnecessary.
All build artifacts live in an out-of-tree directory, ``../.dev/kernel`` by
default. The host kernel is not replaced and the driver is not loaded on it.

The experimental driver downloads boot firmware, then performs a per-device
vendor HCC/BSLE handshake and controller metadata queries in runtime mode.
Its current final state is ``native-runtime-setup``. This is not SparkLink
Ready: complete native discovery transactions and real RF validation remain required. Transport binding,
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
