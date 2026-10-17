#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# sparklink QEMU integration test runner
#
# Builds the test program, creates a minimal initramfs, boots the
# kernel in QEMU, runs all sparklink test cases, and reports results.
#
# Requirements:
#   - qemu-system-x86_64
#   - busybox (static build)
#   - gcc (for test program compilation)
#   - Built kernel at $KBUILD (default: ../../build)
#
# Usage:
#   ./run_qemu_test.sh            # Run tests
#   ./run_qemu_test.sh --verbose  # Show full QEMU console output
#   QEMU_BIN=/path/to/custom/qemu-system-x86_64 ./run_qemu_test.sh
#   SLE_DLI_DEVICE=1 ./run_qemu_test.sh  # Enable usb-sle-dli device
#   SLE_DLI_DEVICE=2 ./run_qemu_test.sh  # Enable 2 usb-sle-dli devices (multi-device)
#   python3 test_verdict.py      # Validate verdicts without booting a guest
#
# Exit status: 0 complete pass, 1 failure, 4 skipped/incomplete suite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINUX_SRC="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
KBUILD="${KBUILD:-$LINUX_SRC/build}"
BZIMAGE="$KBUILD/arch/x86/boot/bzImage"
WORKDIR="$SCRIPT_DIR/.qemu_test"
QEMU_BIN_EXPLICIT="${QEMU_BIN+x}"
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
SLE_DLI_DEVICE="${SLE_DLI_DEVICE:-2}"

VERBOSE=0
case "${1:-}" in
    --verbose) VERBOSE=1 ;;
    "") ;;
    *) echo "Usage: $0 [--verbose]" >&2; exit 1 ;;
esac
if (( $# > 1 )); then
    echo "Usage: $0 [--verbose]" >&2
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[FAIL]${NC}  $*"; }

TEST_BIN=""
cleanup() {
    if [[ -n "$TEST_BIN" ]]; then
        rm -f "$TEST_BIN"
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 1: Verify prerequisites
# ---------------------------------------------------------------------------

info "Checking prerequisites..."

# A requested controller model is a prerequisite, never an optional fallback.
if [[ ! "$SLE_DLI_DEVICE" =~ ^(0|[1-9]|1[0-6])$ ]]; then
    error "SLE_DLI_DEVICE must be an integer from 0 to 16"
    exit 1
fi
SLE_DEV_COUNT="$SLE_DLI_DEVICE"
if (( SLE_DEV_COUNT == 0 )); then
    warn "SKIP: the full integration suite requires a USB controller; SLE_DLI_DEVICE=0 disables it"
    exit 4
fi
CUSTOM_QEMU_DIR="$SCRIPT_DIR/qemu-sle-dli/bin/bin"
if [[ -z "$QEMU_BIN_EXPLICIT" && -x "$CUSTOM_QEMU_DIR/qemu-system-x86_64" ]]; then
    QEMU_BIN="$CUSTOM_QEMU_DIR/qemu-system-x86_64"
fi
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    error "QEMU executable not found: $QEMU_BIN"
    exit 1
fi
if ! MODEL_HELP=$("$QEMU_BIN" -device help 2>&1); then
    error "Cannot query device models from $QEMU_BIN"
    exit 1
fi
if ! grep -q 'name "usb-sle-dli"' <<< "$MODEL_HELP"; then
    warn "SKIP: $QEMU_BIN does not provide the requested usb-sle-dli model"
    warn "Build custom QEMU: cd qemu-sle-dli && ./build-qemu.sh"
    exit 4
fi
if ! command -v python3 >/dev/null 2>&1; then
    error "python3 is required to validate the run verdict"
    exit 1
fi

if [[ ! -f "$BZIMAGE" ]]; then
    error "Kernel image not found: $BZIMAGE"
    echo "  Build the kernel first: make O=build -j\$(nproc)"
    exit 1
fi

# Kconfig can silently drop Rust-dependent drivers when rust-src is missing.
# This runner loads no modules, so the tested subsystem must be built in.
for option in RUST SPARKLINK; do
    if ! grep -Fxq "CONFIG_$option=y" "$KBUILD/.config"; then
        error "CONFIG_$option=y is required in $KBUILD/.config"
        exit 1
    fi
done

BUSYBOX="$(which busybox 2>/dev/null || true)"
if [[ -z "$BUSYBOX" ]]; then
    error "busybox not found (needed for initramfs)"
    echo "  Install: sudo apt install busybox-static"
    exit 1
fi

if ! file "$BUSYBOX" | grep -q "statically linked"; then
    error "busybox must be statically linked"
    exit 1
fi

info "  bzImage: $BZIMAGE"
info "  busybox: $BUSYBOX"

# ---------------------------------------------------------------------------
# Step 2: Build test program (static)
# ---------------------------------------------------------------------------

info "Building sparklink_test (static)..."

TEST_SRC="$SCRIPT_DIR/sparklink_test.c"
TEST_BIN="$SCRIPT_DIR/sparklink_test_static"

gcc -Wall -Wextra -O2 -static \
    -o "$TEST_BIN" "$TEST_SRC"

info "  Built: $TEST_BIN"
mkdir -p "$WORKDIR"
EXPECTED_CASES="$WORKDIR/expected-cases.txt"
"$TEST_BIN" --list-tests > "$EXPECTED_CASES"

# ---------------------------------------------------------------------------
# Step 3: Create minimal initramfs
# ---------------------------------------------------------------------------

info "Creating initramfs..."

mkdir -p "$WORKDIR/initramfs"/{bin,dev,proc,sys,tmp}

# Copy busybox
cp "$BUSYBOX" "$WORKDIR/initramfs/bin/busybox"
chmod 755 "$WORKDIR/initramfs/bin/busybox"

# Create busybox symlinks
for cmd in sh cat echo ls mkdir mount umount mdev sleep poweroff find grep wc head readlink dmesg; do
    ln -sf busybox "$WORKDIR/initramfs/bin/$cmd"
done

# Copy test binary
cp "$TEST_BIN" "$WORKDIR/initramfs/bin/sparklink_test"
chmod 755 "$WORKDIR/initramfs/bin/sparklink_test"

# Create init script
cat > "$WORKDIR/initramfs/init" << 'INIT_EOF'
#!/bin/sh
# Minimal init for sparklink QEMU test

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || mdev -s
mount -t debugfs none /sys/kernel/debug 2>/dev/null

echo "========================================"
echo "SparkLink QEMU Integration Test"
echo "========================================"
echo ""

# Wait for /dev/sparklink to appear
RETRY=0
MAX_RETRY=30
while [ ! -c /dev/sparklink ] && [ $RETRY -lt $MAX_RETRY ]; do
    sleep 0.1
    RETRY=$((RETRY + 1))
done

if [ ! -c /dev/sparklink ]; then
    echo "QEMU_TEST_RESULT: FAIL (device /dev/sparklink not found)"
    echo ""
    echo "Available devices:"
    ls -la /dev/ 2>/dev/null | head -20
    echo ""
    echo "Kernel log:"
    dmesg 2>/dev/null | head -30
    poweroff -f
    exit 1
fi

echo "Device /dev/sparklink found"
echo ""

# Require all requested USB controllers to enumerate and bind before testing.
EXPECTED_USB=0
for option in $(cat /proc/cmdline); do
    case "$option" in
        sparklink.expected_usb=*) EXPECTED_USB=${option#*=} ;;
    esac
done
RETRY=0
MAX_USB_RETRY=50
while [ $RETRY -lt $MAX_USB_RETRY ]; do
    USB_COUNT=0
    BOUND_COUNT=0
    for device in /sys/bus/usb/devices/*; do
        [ -f "$device/idVendor" ] || continue
        [ "$(cat "$device/idVendor")" = "1234" ] || continue
        [ "$(cat "$device/idProduct")" = "5678" ] || continue
        USB_COUNT=$((USB_COUNT + 1))
        DRIVER=$(readlink "$device:1.0/driver")
        if [ "${DRIVER##*/}" = "sparklink_usb" ]; then
            BOUND_COUNT=$((BOUND_COUNT + 1))
        fi
    done
    if [ "$EXPECTED_USB" -gt 0 ] && [ "$USB_COUNT" -eq "$EXPECTED_USB" ] && \
       [ "$BOUND_COUNT" -eq "$EXPECTED_USB" ]; then
        break
    fi
    sleep 0.1
    RETRY=$((RETRY + 1))
done
if [ "$EXPECTED_USB" -le 0 ] || [ "$USB_COUNT" -ne "$EXPECTED_USB" ] || \
   [ "$BOUND_COUNT" -ne "$EXPECTED_USB" ]; then
    echo "SPARKLINK_USB_GATE: FAIL expected=$EXPECTED_USB found=$USB_COUNT bound=$BOUND_COUNT"
    echo "QEMU_TEST_RESULT: FAIL (USB enumeration or binding timeout)"
    poweroff -f
    exit 1
fi
echo "SPARKLINK_USB_GATE: PASS expected=$EXPECTED_USB found=$USB_COUNT bound=$BOUND_COUNT"

# Keep serial case records intact. All printk levels remain in the ring and
# are required below; faults still reject the host verdict after the suite.
if ! dmesg -n 1; then
    echo "QEMU_TEST_RESULT: FAIL (cannot isolate serial case records)"
    poweroff -f
    exit 1
fi

# Run the test suite
/bin/sparklink_test 2>&1
TEST_EXIT=$?

# Require the full ring even after failed assertions. The host verifier scans
# it for warnings/faults and rejects absent or incomplete dump markers.
echo "SPARKLINK_KERNEL_LOG_BEGIN"
if ! dmesg; then
    TEST_EXIT=1
fi
echo "SPARKLINK_KERNEL_LOG_END"

echo ""
echo "========================================"
if [ $TEST_EXIT -eq 0 ]; then
    echo "QEMU_TEST_RESULT: PASS (exit=$TEST_EXIT)"
elif [ $TEST_EXIT -eq 4 ]; then
    echo "QEMU_TEST_RESULT: SKIP (exit=$TEST_EXIT)"
else
    echo "QEMU_TEST_RESULT: FAIL (exit=$TEST_EXIT)"
fi
echo "========================================"

# Power off the VM
poweroff -f
INIT_EOF

chmod 755 "$WORKDIR/initramfs/init"

# Build initramfs cpio
(cd "$WORKDIR/initramfs" && find . | cpio -o -H newc --quiet 2>/dev/null | gzip) > "$WORKDIR/initramfs.cpio.gz"

INITRAMFS_SIZE=$(du -h "$WORKDIR/initramfs.cpio.gz" | cut -f1)
info "  initramfs: $WORKDIR/initramfs.cpio.gz ($INITRAMFS_SIZE)"

# ---------------------------------------------------------------------------
# Step 4: Run QEMU
# ---------------------------------------------------------------------------

CONSOLE_LOG="$WORKDIR/console.log"
TIMEOUT=120

info "Starting QEMU (timeout=${TIMEOUT}s)..."

# Detect KVM support
KVM_OPTS=()
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    KVM_OPTS=(-enable-kvm)
fi

SLE_USB_OPTS=(-device qemu-xhci,id=xhci)
for (( i=0; i<SLE_DEV_COUNT; i++ )); do
    SLE_USB_OPTS+=(-device usb-sle-dli,bus=xhci.0)
done
info "Using $QEMU_BIN with $SLE_DEV_COUNT usb-sle-dli device(s)"

# A failed launch must not reuse a preceding run's successful console log.
: > "$CONSOLE_LOG"

set +e
timeout "$TIMEOUT" "$QEMU_BIN" \
    -kernel "$BZIMAGE" \
    -initrd "$WORKDIR/initramfs.cpio.gz" \
    -append "console=ttyS0 earlyprintk=serial loglevel=5 log_buf_len=4M panic=1 oops=panic sparklink.expected_usb=$SLE_DEV_COUNT" \
    -serial "file:$CONSOLE_LOG" \
    -display none \
    -no-reboot \
    -m 256M \
    -smp 2 \
    "${KVM_OPTS[@]}" \
    "${SLE_USB_OPTS[@]}" \
    2>"$WORKDIR/qemu_stderr.log"
QEMU_EXIT=$?
set -e

if [[ $VERBOSE -eq 1 ]] && [[ -f "$CONSOLE_LOG" ]]; then
    cat "$CONSOLE_LOG"
fi

# ---------------------------------------------------------------------------
# Step 5: Analyze results
# ---------------------------------------------------------------------------

echo ""
info "Analyzing results..."

# Count OK/FAIL/WARN lines (anchor to line start to avoid kernel log noise)
OK_COUNT=$(grep -c "^  OK:" "$CONSOLE_LOG" 2>/dev/null || true)
FAIL_COUNT=$(grep -c "^  FAIL:" "$CONSOLE_LOG" 2>/dev/null || true)
WARN_COUNT=$(grep -c "^  WARN:" "$CONSOLE_LOG" 2>/dev/null || true)

echo ""
echo "Test results: ${OK_COUNT} OK, ${FAIL_COUNT} FAIL, ${WARN_COUNT} WARN"

python3 "$SCRIPT_DIR/qemu_verdict.py" \
    --console "$CONSOLE_LOG" --expected-cases "$EXPECTED_CASES" \
    --qemu-exit "$QEMU_EXIT" --expected-usb "$SLE_DEV_COUNT"
