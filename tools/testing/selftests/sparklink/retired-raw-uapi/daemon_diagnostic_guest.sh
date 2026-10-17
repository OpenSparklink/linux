#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Sourced by the daemon lifecycle gate. Synthetic USB only, never real RF.
tool_target() {
    tool_index=${1#/org/sparklink/slk}; tool_index=${tool_index%%_g*}
    tool_generation=${1##*_g}
}
tool() { /bin/slkconfig --adapter "$tool_index" --generation "$tool_generation" "$@"; }
tool_denied() {
    pattern=$1; shift
    "$@" > /tmp/tool-denied 2>&1 && fail 'diagnostic negative unexpectedly succeeded'
    grep -q "$pattern" /tmp/tool-denied || { cat /tmp/tool-denied; fail 'diagnostic expected denial missing'; }
}
tool_managed() {
    tool_target "$1"
    echo 'TOOL_DIAGNOSTIC_BEGIN'
    [ "$(user 'id -u')" = 1000 ] || fail 'diagnostic ordinary uid'
    user 'grep CapEff /proc/self/status' | grep -q '0000000000000000' || fail 'diagnostic ordinary capabilities'
    user "/bin/slkconfig --adapter $tool_index --generation $tool_generation controller" > /tmp/tool-baseline || fail 'ordinary controller snapshot'
    user "/bin/slkconfig --adapter $tool_index --generation $tool_generation management" > /tmp/tool-owner || fail 'ordinary owner observation'
    grep -q "state=1 mode=1 owning_fd=0 error=0" /tmp/tool-owner || fail 'observer token/owner state'
    tool_denied EBUSY tool query mac
    tool_denied EPERM user "/bin/slkconfig --adapter $tool_index --generation $tool_generation query mac"
    tool_denied 'select a registration' /bin/slkconfig --device /missing-device --generation "$tool_generation" query mac
    tool_denied 'requires --generation' /bin/slkconfig --device /missing-device --adapter "$tool_index" query mac
    tool_denied ENODEV /bin/slkconfig --adapter "$tool_index" --generation "$((tool_generation+100))" controller
    tool_denied 'legacy management command is unsupported' tool reset
    user "/bin/slkconfig --adapter $tool_index --generation $tool_generation controller" > /tmp/tool-after || fail 'ordinary after-denial snapshot'
    /bin/busybox cmp /tmp/tool-baseline /tmp/tool-after || fail 'denied queries changed selected queue/state'
    echo "TOOL_DIAGNOSTIC_DENIALS: index=$tool_index generation=$tool_generation managed_busy=1 uid1000_caps0=1 schema=2 stale=1 legacy_reset=1 no_admission=1 observer=1"
}
tool_released() {
    for target in "$1" "$2"; do
        tool_target "$target"
        /bin/daemon-management "$target" seed off || fail 'unread seed reply'
        tool query features > /tmp/tool-query || fail 'diagnostic features after stale reply'
        cat /tmp/tool-query
        grep -Eq 'drained=[23] ' /tmp/tool-query || fail 'stale Status/Complete not discarded'
        for query in mac version buffers; do
            tool query "$query" > /tmp/tool-query || fail 'diagnostic query'
            cat /tmp/tool-query
            grep -Eq 'drained=[01] ' /tmp/tool-query || fail 'unexpected stale replies beyond optional credit notification'
        done
        tool management > /tmp/tool-free || fail 'query owner released'
        grep -q 'state=0 mode=0 owning_fd=0 error=0' /tmp/tool-free || fail 'diagnostic lease not Free'
    done
    echo 'TOOL_DIAGNOSTIC_END: queried=2 queries=8 stale_commands=2 stale_pairs=2 free=2'
}
