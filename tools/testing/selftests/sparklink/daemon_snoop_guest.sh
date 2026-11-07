#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Root diagnostic tools run alongside managed slkd; slctl remains uid 1000.
snoop_identity() {
    snoop_index=${1#/org/sparklink/slk}; snoop_generation=${snoop_index#*_g}; snoop_index=${snoop_index%_g*}
}
snoop_wait_file() {
    for snoop_n in $(seq 1 100); do
        [ -f "$1" ] && [ "$(/bin/busybox wc -c < "$1")" -ge 16 ] && return 0
        sleep 0.1
    done
    fail "snoop subscription not activated: $1"
}
snoop_export() {
    echo "SNOOP_CAPTURE_BEGIN: name=$1 bytes=$(/bin/busybox wc -c < "$2")"
    /bin/busybox base64 "$2" || fail 'snoop export'
    echo "SNOOP_CAPTURE_END: name=$1"
}
snoop_begin() {
    /bin/daemon-snoop contract "$1" || fail 'snoop syscall contract'
    snoop_identity "$1"
    if user "/bin/slkmon --adapter $snoop_index --generation $snoop_generation --count 1 --write /tmp/denied.snoop" > /tmp/snoop-denied.out 2>&1; then fail 'ordinary raw snoop admitted'; fi
    grep -q 'EPERM' /tmp/snoop-denied.out || fail 'ordinary snoop denial wrong'
    [ ! -e /tmp/denied.snoop ] || fail 'denied snoop created evidence'
    /bin/slkmon --adapter "$snoop_index" --generation "$snoop_generation" --count 32 --write /tmp/mon.snoop > /tmp/mon.out 2>&1 & snoop_mon=$!
    /bin/slkdump --adapter "$snoop_index" --generation "$snoop_generation" --count 32 --write /tmp/dump.snoop > /tmp/dump.out 2>&1 & snoop_dump=$!
    snoop_wait_file /tmp/mon.snoop; snoop_wait_file /tmp/dump.snoop
    kill -0 "$snoop_mon" && kill -0 "$snoop_dump" || fail 'snoop tools terminated before traffic'
    echo "SNOOP_STARTED: index=$snoop_index generation=$snoop_generation tools=2 uid1000_denied=1"
}
snoop_finish() {
    wait "$snoop_mon" || { cat /tmp/mon.out; fail 'slkmon capture'; }
    wait "$snoop_dump" || { cat /tmp/dump.out; fail 'slkdump capture'; }
    /bin/daemon-snoop files "$1" /tmp/mon.snoop /tmp/dump.snoop || fail 'snoop capture comparison'
    /bin/daemon-snoop slow "$1" || fail 'snoop overflow/reopen'
    snoop_export mon /tmp/mon.snoop; snoop_export dump /tmp/dump.snoop
}
snoop_before_remove() {
    snoop_identity "$1"
    /bin/slkmon --adapter "$snoop_index" --generation "$snoop_generation" --filter 0xffff --write /tmp/retired.snoop > /tmp/retired.out 2>&1 & snoop_retired=$!
    snoop_wait_file /tmp/retired.snoop
    /bin/daemon-snoop watch "$1" > /tmp/snoop-watch.out 2>&1 & snoop_watch=$!
    for snoop_n in $(seq 1 100); do
        grep -q '^SNOOP_ARMED:' /tmp/snoop-watch.out && return 0
        sleep 0.1
    done
    cat /tmp/snoop-watch.out; fail 'snoop retirement watch not armed'
}
snoop_removed() {
    wait "$snoop_watch" || { cat /tmp/snoop-watch.out; fail 'snoop retirement syscall'; }
    cat /tmp/snoop-watch.out
    if wait "$snoop_retired"; then fail 'retired slkmon did not fail'; fi
    grep -q 'ENODEV' /tmp/retired.out || { cat /tmp/retired.out; fail 'retired tool error'; }
    echo 'SNOOP_TOOL_RETIRED: terminal=ENODEV'
}
snoop_replug() {
    snoop_identity "$1"
    snoop_new=$snoop_generation
    snoop_identity "$2"
    if /bin/slkmon --adapter "$snoop_index" --generation "$snoop_generation" --count 1 --write /tmp/stale.snoop > /tmp/snoop-stale.out 2>&1; then fail 'stale monitor retargeted'; fi
    grep -q 'ENODEV' /tmp/snoop-stale.out || fail 'stale monitor error'
    [ ! -e /tmp/stale.snoop ] || fail 'stale monitor wrote evidence'
    /bin/slkmon --adapter "$snoop_index" --generation "$snoop_new" --count 4 --write /tmp/replug.snoop > /tmp/replug.out 2>&1 || { cat /tmp/replug.out; fail 'new generation capture'; }
    echo "SNOOP_REPLUG: index=$snoop_index old_generation=$snoop_generation new_generation=$snoop_new records=4 stale=ENODEV"
    snoop_export replug /tmp/replug.snoop
}
