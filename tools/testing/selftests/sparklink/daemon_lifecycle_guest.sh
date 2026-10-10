#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Synthetic controller lifecycle only; this is never real RF acceptance.
export PATH=/bin
fail() { echo "DAEMON_FAILURE: $*"; cat /tmp/slkd.log; exit 1; }
user() { su ws73 -s /bin/sh -c "$*"; }
ctl() { user "/bin/slctl --session $*"; }
list() { ctl list | grep '^  /org/sparklink/'; }
wait_ready() {
    for n in $(seq 1 100); do
        paths=$(list 2>/dev/null)
        count=$(printf '%s\n' "$paths" | grep -c '^  /org/sparklink/')
        ready=0
        for path in $paths; do
            ctl --adapter "$path" show > /tmp/show.out 2>&1 || continue
            grep -q 'State:       Ready' /tmp/show.out && ready=$((ready + 1))
        done
        [ "$count" = "$1" ] && [ "$ready" = "$1" ] && return 0
        sleep 0.1
    done
    fail "expected $1 independent Ready adapters"
}
[ "$(user 'id -u')" = 1000 ] || fail 'ordinary application uid'
echo 'DAEMON_UID: 1000'
daemon_uid=0
/bin/slkd --session --storage /tmp/bonds -n > /tmp/slkd.log 2>&1 &
wait_ready 1
pid=$(pidof slkd)
[ -n "$pid" ] || fail 'daemon pid'
ctl daemon > /tmp/daemon-before || fail 'bus-authenticated daemon identity'
grep -Eq "^DaemonIdentity: owner=:[0-9]+\.[0-9]+ pid=$pid uid=$daemon_uid$" /tmp/daemon-before || fail 'daemon bus PID/UID mismatch'
first=$(list | awk '{print $1}')
if [ "$SPARKLINK_TEST_KERNEL_AUTHORIZATION" = 1 ]; then
    /bin/kernel-authorization "$first" || fail 'kernel permission matrix'
fi
if [ "$SPARKLINK_TEST_PRODUCTION_POLICY" = 1 ]; then
    [ "$(su observer -s /bin/sh -c 'id -u')" = 1001 ] || fail 'observer uid'
    [ "$(user 'id -g')" = 1002 ] || fail 'distinct primary group'
    user 'id -G' | grep -Eq '(^| )1000( |$)' || fail 'supplementary control group'
    if su observer -s /bin/sh -c '[ -r /dev/sparklink ] || [ -w /dev/sparklink ]'; then fail 'observer has direct chardev access'; fi
    su observer -s /bin/sh -c "/bin/bus-policy-probe $first observer" || fail 'observer policy matrix'
    user "/bin/bus-policy-probe $first control" || fail 'control group policy matrix'
    echo 'DAEMON_AUTHORIZATION: observer-uid=1001 control-uid=1000 control-primary-gid=1002 control-supplementary-gid=1000 daemon-uid=0 read=allowed control=denied observer-denials=16 control-own=denied'
fi
ctl --adapter "$first" show || fail 'first show'
echo 'DAEMON_ADD_SECOND'
wait_ready 2
second=$(list | grep -v "$first" | awk '{print $1}')
[ -n "$second" ] || fail 'distinct second registration'
ctl --adapter "$second" show || fail 'second show'
[ "$(pidof slkd)" = "$pid" ] || fail 'daemon restarted before removal'
if [ "$SPARKLINK_TEST_RADIO" = 1 ]; then
    . /bin/test-radio
    radio_rounds 20 "$first" "$second" initial
fi
echo 'DAEMON_REMOVE_FIRST'
wait_ready 1
[ "$(list | awk '{print $1}')" = "$second" ] || fail 'unaffected registration changed'
ctl --adapter "$second" show || fail 'survivor not usable'
if ctl --adapter "$first" show > /tmp/stale.out 2>&1; then fail 'stale selection reached survivor'; fi
grep -q 'not a live registration' /tmp/stale.out || fail 'stale selection error missing'
echo 'DAEMON_STALE_SELECTION: rejected'
echo 'DAEMON_READD_FIRST'
wait_ready 2
replacement=$(list | grep -v "$second" | awk '{print $1}')
[ -n "$replacement" ] && [ "$replacement" != "$first" ] || fail 'registration generation not replaced'
ctl --adapter "$replacement" show || fail 'replacement not Ready'
ctl --adapter "$second" show || fail 'survivor changed after replug'
[ "$(pidof slkd)" = "$pid" ] || fail 'daemon restarted during hotplug'
if [ "$SPARKLINK_TEST_RADIO" = 1 ]; then
    radio_rounds 2 "$replacement" "$second" replug
fi
ctl daemon > /tmp/daemon-after || fail 'daemon bus identity after replug'
/bin/busybox cmp /tmp/daemon-before /tmp/daemon-after || fail 'daemon bus owner changed'
owner=$(awk '{sub(/^owner=/,"",$2);print $2}' /tmp/daemon-after)
echo "DAEMON_BUS_IDENTITY: pid=$pid uid=$daemon_uid owner=$owner same_owner=1"
echo 'DAEMON_HOTPLUG: independent=2 same_process=1 new_generation=1'
if [ "$SPARKLINK_TEST_MANAGEMENT_HANDOFF" = 1 ]; then
    echo 'DAEMON_MANAGEMENT_BEGIN'
    # Leave both domains running. Shutdown must stop them, not rely on the
    # previous rounds' explicit application stops or a USB generation change.
    ctl --adapter "$replacement" advertise on > /tmp/handoff-adv || fail 'handoff advertiser'
    ctl --adapter "$second" scan on > /tmp/handoff-scan || fail 'handoff scanner'
    /bin/daemon-management "$replacement" held advertising || fail 'advertising owner'
    /bin/daemon-management "$second" held scanning || fail 'scanning owner'
    if [ "$SPARKLINK_TEST_DIAGNOSTIC_TOOLS" = 1 ]; then
        . /bin/test-diagnostic
        tool_managed "$replacement"
    fi
    kill -TERM "$pid"
else
    kill -INT "$pid"
fi
for n in $(seq 1 100); do [ -z "$(pidof slkd)" ] && break; sleep 0.1; done
[ -z "$(pidof slkd)" ] || fail 'daemon shutdown timeout'
cat /tmp/slkd.log
if [ "$SPARKLINK_TEST_MANAGEMENT_HANDOFF" = 1 ]; then
    # Each worker observes Free while its own Arc<Adapter> is still alive.
    [ "$(grep -c 'adapter management relinquished while fd retained' /tmp/slkd.log)" = 2 ] || fail 'explicit release missing'
    grep -q 'adapter management cleanup failed' /tmp/slkd.log && fail 'cleanup fault'
    /bin/daemon-management "$replacement" free off || fail 'advertiser not stopped/free'
    /bin/daemon-management "$second" free off || fail 'scanner not stopped/free'
    echo 'DAEMON_MANAGEMENT_RELEASE: signal=TERM retained_fd=2 actual_stop=2 free=2'
    if [ "$SPARKLINK_TEST_DIAGNOSTIC_TOOLS" = 1 ]; then
        tool_released "$replacement" "$second"
    fi
    /bin/slkd --session --storage /tmp/bonds -n > /tmp/slkd-restarted.log 2>&1 &
    wait_ready 2
    next_pid=$(pidof slkd)
    [ -n "$next_pid" ] && [ "$next_pid" != "$pid" ] || fail 'new daemon PID'
    ctl daemon > /tmp/daemon-restarted || fail 'new daemon bus identity'
    grep -Eq "^DaemonIdentity: owner=:[0-9]+\.[0-9]+ pid=$next_pid uid=$daemon_uid$" /tmp/daemon-restarted || fail 'new bus PID/UID'
    next_owner=$(awk '{sub(/^owner=/,"",$2);print $2}' /tmp/daemon-restarted)
    [ "$next_owner" != "$owner" ] || fail 'new bus owner'
    actual=$(list | awk '{print $1}' | /bin/busybox sort) || fail 'restart adapter list'
    expected=$(printf '%s\n' "$replacement" "$second" | /bin/busybox sort) || fail 'restart expected list'
    [ -n "$actual" ] && [ "$actual" = "$expected" ] || fail 'restart reused/replaced registration'
    /bin/daemon-management "$replacement" held off || fail 'new advertising owner'
    /bin/daemon-management "$second" held off || fail 'new scanning owner'
    echo "DAEMON_MANAGEMENT_RESTART: old_pid=$pid new_pid=$next_pid old_owner=$owner new_owner=$next_owner same_generation=2 ready=2"
    kill -INT "$next_pid"
    for n in $(seq 1 100); do [ -z "$(pidof slkd)" ] && break; sleep 0.1; done
    [ -z "$(pidof slkd)" ] || fail 'successor shutdown timeout'
    cat /tmp/slkd-restarted.log
    [ "$(grep -c 'adapter management relinquished while fd retained' /tmp/slkd-restarted.log)" = 2 ] || fail 'successor explicit release missing'
    grep -q 'adapter management cleanup failed' /tmp/slkd-restarted.log && fail 'successor cleanup fault'
    /bin/daemon-management "$replacement" free off || fail 'successor advertiser free'
    /bin/daemon-management "$second" free off || fail 'successor scanner free'
    echo 'DAEMON_MANAGEMENT_END: signal=INT free=2'
fi
echo 'DAEMON_LIFECYCLE: PASS'
