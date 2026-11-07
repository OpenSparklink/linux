#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Sourced by the lifecycle fixture. Explicitly synthetic medium, not real RF.
radio_rounds() {
    set -o pipefail
    count=$1
    tx=$2
    rx=$3
    for round in $(seq 1 "$count"); do
        ctl --adapter "$tx" show > /tmp/tx-view || fail 'tx metadata'
        address=$(awk '/  Address:/ {print $2}' /tmp/tx-view)
        ctl --adapter "$tx" advertise on 2>&1 | /bin/busybox tee /tmp/tx-operation || fail 'advertise transaction'
        marker=$(awk '/NativeAdvertisementAccepted:/ {for (i=1;i<=NF;i++) if ($i ~ /^marker=/) {sub(/^marker=/,"",$i);print $i}}' /tmp/tx-operation)
        [ "${#marker}" = 32 ] || fail 'fresh marker length'
        grep -q 'operation=1 state=3 errno=0 status=0x00.*power=-42 power_valid=1 adv=2 scan=1' /tmp/tx-operation || fail 'adv complete/actual power'
        ctl --adapter "$rx" scan on "$marker" "$address" 2>&1 | /bin/busybox tee /tmp/rx-operation || { ctl --adapter "$rx" reports; fail 'scan or fresh report matching'; }
        grep -q 'operation=3 state=3 errno=0 status=0x00.*adv=1 scan=2' /tmp/rx-operation || fail 'scan Complete'
        grep -q "NativeDiscoveryMatch:.*address=$address RSSI=-42 marker=$marker" /tmp/rx-operation || fail 'received identity/data/RSSI'
        echo "DAEMON_RADIO_ROUND: phase=$4 round=$round tx=$tx rx=$rx marker=$marker"
        ctl --adapter "$tx" advertise off > /tmp/tx-stop || fail 'advertise stop'
        ctl --adapter "$rx" scan off > /tmp/rx-stop || fail 'scan stop'
        cat /tmp/tx-stop /tmp/rx-stop
        # Switch the two actual adapter paths every round.
        swap=$tx; tx=$rx; rx=$swap
    done
    # A stopped transmitter must not manufacture a new report when RX restarts.
    ctl --adapter "$rx" reports > /tmp/reports-before || fail 'negative baseline'
    ctl --adapter "$rx" scan on > /tmp/negative-scan || fail 'negative scan transaction'
    sleep 2
    ctl --adapter "$rx" reports > /tmp/reports-after || fail 'negative observation'
    /bin/busybox cmp /tmp/reports-before /tmp/reports-after || fail 'report appeared with both transmitters stopped'
    ctl --adapter "$rx" scan off > /tmp/negative-stop || fail 'negative scan stop'
    echo "DAEMON_RADIO_NEGATIVE: phase=$4 no_new_report=1 duration_ms=2000"
}
