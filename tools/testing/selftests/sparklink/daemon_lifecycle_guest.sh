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
        paths=$(list)
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
user 'exec /bin/slkd --session --storage /tmp/bonds -n' > /tmp/slkd.log 2>&1 &
wait_ready 1
pid=$(pidof slkd)
[ -n "$pid" ] || fail 'daemon pid'
first=$(list | awk '{print $1}')
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
echo 'DAEMON_HOTPLUG: independent=2 same_process=1 new_generation=1'
kill -INT "$pid"
for n in $(seq 1 100); do [ -z "$(pidof slkd)" ] && break; sleep 0.1; done
[ -z "$(pidof slkd)" ] || fail 'daemon shutdown timeout'
cat /tmp/slkd.log
echo 'DAEMON_LIFECYCLE: PASS'
