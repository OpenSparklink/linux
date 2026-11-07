# SPDX-License-Identifier: GPL-2.0-only
import base64
import struct
import unittest
from snoop_verdict import HEADER, RECORD, assess_snoop, capture_files
from test_daemon_lifecycle import GOOD


def capture(index, generation, count, report=False):
    out = bytearray(HEADER)
    for seq in range(1,count+1):
        direction = 2
        packet = b'\xa1\x02\x04\x00\x00'
        if report and seq == 2:
            direction = 1
            body = bytearray(23)
            body[2:8] = b'\x02\x73\x00\x00\x00\x01'
            body[21] = 214; body[22] = 16
            body += bytes.fromhex('01'*16)
            packet = b'\xa2\x0b\x18' + struct.pack('<H',len(body)) + body
        out += RECORD.pack(seq,generation,seq*1000,0,1,len(packet),0,index,direction,1,len(packet),0,0,packet.ljust(320,b'\0'))
    return bytes(out)


def export(name, data):
    return f'SNOOP_CAPTURE_BEGIN: name={name} bytes={len(data)}\n'+base64.b64encode(data).decode()+f'\nSNOOP_CAPTURE_END: name={name}\n'


class SnoopVerdict(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mon = capture(1,2,32,True)
        cls.replug = capture(0,3,4)
        before = ('SNOOP_CONTRACT: index=1 generation=2 readers=2 schema=5 copyout=1 mixed=2 inherited_uid1001=1 cap_denied=1 poll_denied=1 no_admission=1\n'
                  'SNOOP_STARTED: index=1 generation=2 tools=2 uid1000_denied=1\n'
                  'NativeDiscoveryMatch: generation=2 seq=1 address=02:73:00:00:00:01 RSSI=-42 marker='+'01'*16+' data='+'01'*16+' kernel_boottime_ns=1 elapsed_ms=1 lost=0\n'
                  'SNOOP_TOOLS: index=1 generation=2 records=32 identical=1 tx=1 rx=1 report=1 loss=0\n'
                  'SNOOP_SLOW: index=1 generation=2 lost=100 reopen=1 independent=1\n'+export('mon',cls.mon)+export('dump',cls.mon))
        removed = ('SNOOP_ARMED: index=0 generation=1\nSNOOP_RETIRED: index=0 generation=1 poll=ERR_HUP query=ENODEV\n'
                   'SNOOP_TOOL_RETIRED: terminal=ENODEV\n')
        replug = 'SNOOP_REPLUG: index=0 old_generation=1 new_generation=3 records=4 stale=ENODEV\n'+export('replug',cls.replug)
        cls.good = GOOD.replace('DAEMON_REMOVE_FIRST',before+'DAEMON_REMOVE_FIRST').replace('DAEMON_READD_FIRST',removed+'DAEMON_READD_FIRST').replace('DAEMON_HOTPLUG:',replug+'DAEMON_HOTPLUG:')

    def mutate_capture(self, offset, value):
        data=bytearray(self.mon);data[offset]=value
        return self.good.replace(export('mon',self.mon),export('mon',data)).replace(export('dump',self.mon),export('dump',data))
    def test_complete(self): self.assertEqual(assess_snoop(self.good),[])
    def test_binary_export(self): self.assertEqual(capture_files(self.good)['mon'],self.mon)
    def test_corrupt_data(self): self.assertTrue(assess_snoop(self.mutate_capture(16+376+56+28,2)))
    def test_wrong_rssi(self): self.assertTrue(assess_snoop(self.good.replace('RSSI=-42','RSSI=-41')))
    def test_generation(self): self.assertTrue(assess_snoop(self.mutate_capture(16+8,3)))
    def test_padding(self): self.assertTrue(assess_snoop(self.mutate_capture(16+375,1)))
    def test_loss(self): self.assertTrue(assess_snoop(self.mutate_capture(16+24,1)))
    def test_transport_error(self): self.assertTrue(assess_snoop(self.mutate_capture(16+40,1)))
    def test_truncated(self): self.assertTrue(assess_snoop(self.mutate_capture(16+50,1)))
    def test_duplicate_capture(self): self.assertTrue(assess_snoop(self.good+export('mon',self.mon)))
    def test_tool_mismatch(self): self.assertTrue(assess_snoop(self.good.replace(export('dump',self.mon),export('dump',capture(1,2,32)))))
    def test_copyout(self): self.assertTrue(assess_snoop(self.good.replace('copyout=1','copyout=0')))
    def test_capability(self): self.assertTrue(assess_snoop(self.good.replace('cap_denied=1','cap_denied=0')))
    def test_poll_hup(self): self.assertTrue(assess_snoop(self.good.replace('poll=ERR_HUP','poll=IN')))
    def test_replug_reuse(self): self.assertTrue(assess_snoop(self.good.replace('new_generation=3','new_generation=1')))
    def test_slow_no_loss(self): self.assertTrue(assess_snoop(self.good.replace('lost=100','lost=0')))
    def test_no_independent_domain_report(self): self.assertTrue(assess_snoop(self.good.replace('NativeDiscoveryMatch:','removed:')))
    def test_bad_base64(self): self.assertTrue(assess_snoop(self.good.replace(base64.b64encode(self.mon).decode(),'invalid!',1)))
    def test_missing_end(self): self.assertTrue(assess_snoop(self.good.replace('SNOOP_CAPTURE_END: name=mon','missing')))


if __name__ == '__main__': unittest.main()
