# SPDX-License-Identifier: GPL-2.0-only
"""Validate exported native snoop bytes; synthetic USB is never RF evidence."""
import base64
import re
import struct

RECORD = struct.Struct('<QQQQIIiHBBHHI320s')
HEADER = b'SLKSNP01' + struct.pack('<II', 1, 320)


def capture_files(console):
    blocks = re.findall(r'^SNOOP_CAPTURE_BEGIN: name=(mon|dump|replug) bytes=(\d+)\n([A-Za-z0-9+/=\n]+)^SNOOP_CAPTURE_END: name=(mon|dump|replug)$', console, re.M)
    if ([x[0] for x in blocks] != ['mon', 'dump', 'replug'] or
        console.count('SNOOP_CAPTURE_BEGIN:') != 3 or console.count('SNOOP_CAPTURE_END:') != 3):
        raise ValueError('missing/duplicate/unordered snoop captures')
    result = {}
    for name, length, encoded, end in blocks:
        data = base64.b64decode(encoded.replace('\n', ''), validate=True)
        if name != end or len(data) != int(length):
            raise ValueError('snoop capture length/name mismatch')
        result[name] = data
    return result


def validate_capture(data, index, generation, count):
    if data[:16] != HEADER or len(data) != 16 + count * RECORD.size:
        raise ValueError('snoop capture header/count mismatch')
    seq = timestamp = 0
    directions, reports = set(), []
    for offset in range(16, len(data), RECORD.size):
        s,g,t,lost,profile,original,status,i,d,f,n,flags,reserved,payload = RECORD.unpack_from(data, offset)
        if (s != seq+1 or g != generation or t < timestamp or not t or lost or
            profile != 1 or i != index or d not in [1,2] or f != 1 or flags or reserved or
            status != 0 or n != original or not 5 <= n <= 320 or any(payload[n:]) or
            payload[0] != (0xa2 if d == 1 else 0xa1) or int.from_bytes(payload[3:5], 'little') != n-5):
            raise ValueError('invalid/incomplete snoop record metadata or WS73 framing')
        if d == 1 and payload[1:3] == b'\x0b\x18':
            body = payload[5:n]
            if len(body) < 23 or len(body) != 23 + body[22]:
                raise ValueError('invalid discovery report capture')
            reports.append((str(g), ':'.join(f'{b:02X}' for b in body[2:8]),
                            str(struct.unpack('b', body[21:22])[0]), body[23:].hex()))
        directions.add(d)
        seq, timestamp = s,t
    return directions, reports


def assess_snoop(console):
    errors = []
    if 'SNOOP_FAILURE:' in console:
        errors.append('guest snoop syscall assertion failed')
    views = re.findall(r'^Adapter /org/sparklink/slk(\d+)_g(\d+):', console, re.M)
    if len(views) != 5:
        return errors + ['snoop selected identities missing']
    old,peer,new = views[0],views[1],views[3]
    labels = [f'SNOOP_CONTRACT: index={peer[0]} generation={peer[1]} readers=2 schema=5 copyout=1 mixed=2 inherited_uid1001=1 cap_denied=1 poll_denied=1 no_admission=1',
              f'SNOOP_STARTED: index={peer[0]} generation={peer[1]} tools=2 uid1000_denied=1',
              f'SNOOP_TOOLS: index={peer[0]} generation={peer[1]} records=32 identical=1 tx=1 rx=1 report=1 loss=0',
              f'SNOOP_ARMED: index={old[0]} generation={old[1]}',
              f'SNOOP_RETIRED: index={old[0]} generation={old[1]} poll=ERR_HUP query=ENODEV',
              'SNOOP_TOOL_RETIRED: terminal=ENODEV',
              f'SNOOP_REPLUG: index={new[0]} old_generation={old[1]} new_generation={new[1]} records=4 stale=ENODEV']
    positions = [console.find(label) for label in labels]
    if any(console.count(label) != 1 for label in labels) or positions != sorted(positions):
        errors.append('missing/duplicate/reordered snoop contract/tools/retirement proof')
    slow = re.findall(r'^SNOOP_SLOW: index=(\d+) generation=(\d+) lost=([1-9][0-9]*) reopen=1 independent=1$',console,re.M)
    if len(slow) != 1 or slow[0][:2] != peer or console.count('SNOOP_SLOW:') != 1:
        errors.append('snoop slow reader/reopen loss missing')
    elif not positions[2] < console.find('SNOOP_SLOW:') < console.find('DAEMON_REMOVE_FIRST'):
        errors.append('snoop overflow outside traffic phase')
    # ARMED is emitted by a redirected watch process and printed after removal.
    if (not console.find('DAEMON_ADD_SECOND') < positions[0] < positions[2] < console.find('DAEMON_REMOVE_FIRST') or
        not console.find('DAEMON_REMOVE_FIRST') < positions[3] < positions[5] < console.find('DAEMON_READD_FIRST') or
        not console.find('DAEMON_READD_FIRST') < positions[6] < console.find('DAEMON_HOTPLUG:')):
        errors.append('snoop evidence outside selected lifecycle phase')
    prefixes = ['CONTRACT','STARTED','TOOLS','SLOW','ARMED','RETIRED','TOOL_RETIRED','REPLUG']
    if any(console.count('SNOOP_'+p+':') != 1 for p in prefixes):
        errors.append('snoop evidence count mismatch')
    try:
        captures = capture_files(console)
        if captures['mon'] != captures['dump']:
            raise ValueError('independent tools captured different bytes')
        directions,reports = validate_capture(captures['mon'], int(peer[0]), int(peer[1]),32)
        validate_capture(captures['dump'], int(peer[0]), int(peer[1]),32)
        validate_capture(captures['replug'], int(new[0]), int(new[1]),4)
        observed = re.findall(r'^NativeDiscoveryMatch: generation=(\d+) seq=\d+ address=([0-9A-F:]+) RSSI=(-?\d+) marker=[0-9a-f]{32} data=([0-9a-f]+) ',console,re.M)
        if directions != {1,2} or not reports or any(report not in observed for report in reports):
            raise ValueError('raw RX reports do not match independent slctl address/RSSI/data')
    except (ValueError, struct.error) as error:
        errors.append(str(error))
    return errors
