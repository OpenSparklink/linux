# SPDX-License-Identifier: GPL-2.0-only
import unittest
from run_daemon_lifecycle import assess, assess_radio


def view(index, generation):
    return (f'Adapter /org/sparklink/slk{index}_g{generation}:\n  State:       Ready\n'
            f'  Generation:  {generation}\n  Address:     02:73:00:00:00:02\n  Profile:     1\n')


GOOD = ('DAEMON_UID: 1000\n' + view(0, 1) + 'DAEMON_ADD_SECOND\n' + view(1, 2) +
        'DAEMON_REMOVE_FIRST\n' + view(1, 2) + 'DAEMON_STALE_SELECTION: rejected\n' +
        'DAEMON_READD_FIRST\n' + view(0, 3) + view(1, 2) +
        'DAEMON_HOTPLUG: independent=2 same_process=1 new_generation=1\n'
        'DAEMON_LIFECYCLE: PASS\nDAEMON_GUEST_EXIT: 0\n'
        'DAEMON_KERNEL_LOG_BEGIN\n[    0.000000] early kernel\nDAEMON_KERNEL_LOG_END\n')


class DaemonVerdict(unittest.TestCase):
    def test_complete(self): self.assertEqual(assess(GOOD, 0), [])
    def test_exit(self): self.assertTrue(assess(GOOD, 1))
    def test_root(self): self.assertTrue(assess(GOOD.replace('UID: 1000', 'UID: 0'), 0))
    def test_setup(self): self.assertTrue(assess(GOOD.replace('State:       Ready', 'State:       Setup', 1), 0))
    def test_restart(self): self.assertTrue(assess(GOOD.replace('same_process=1', 'same_process=0'), 0))
    def test_stale(self): self.assertTrue(assess(GOOD.replace('STALE_SELECTION: rejected', 'STALE_SELECTION: accepted'), 0))
    def test_generation_reuse(self): self.assertTrue(assess(GOOD.replace(view(0, 3), view(0, 1)), 0))
    def test_changed_survivor(self): self.assertTrue(assess(GOOD.replace(view(1, 2), view(1, 4), 1), 0))
    def test_failure(self): self.assertTrue(assess(GOOD + 'DAEMON_FAILURE: assertion\n', 0))
    def test_missing_log(self): self.assertTrue(assess(GOOD.replace('DAEMON_KERNEL_LOG_END', 'missing'), 0))
    def test_truncated_log(self): self.assertTrue(assess(GOOD.replace('[    0.000000]', '[    1.000000]'), 0))
    def test_duplicate(self): self.assertTrue(assess(GOOD + 'DAEMON_LIFECYCLE: PASS\n', 0))


class RadioVerdict(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Build a complete transcript independent of the implementation under test.
        out = ['DAEMON_ADD_SECOND', view(0,1).replace('00:02','00:01'), view(1,2)]
        request = 100
        sequence = {}
        for phase, count, a, b in [('initial',20,1,2), ('replug',2,3,2)]:
            if phase == 'replug':
                out += ['DAEMON_REMOVE_FIRST', 'DAEMON_READD_FIRST', view(0,3).replace('00:02','00:03')]
            for n in range(1, count+1):
                tx, rx = (a,b) if n % 2 else (b,a)
                tx_path = f'/org/sparklink/slk{int(tx==2)}_g{tx}'
                rx_path = f'/org/sparklink/slk{int(rx==2)}_g{rx}'
                marker = f'{request:032x}'
                data = (bytes([255,41,1,1,1,11,36]) + ('slk-'+marker).encode()).hex()
                out.append(f'NativeAdvertisementAccepted: request={request} marker={marker} data={data}')
                for op, g, detail in [(1,tx,'0c05 step=2/3 power=-42 power_valid=1 adv=2 scan=1'),(3,rx,'1002 step=1/2 power=0 power_valid=0 adv=1 scan=2')]:
                    out.append(f'NativeOperationResult: generation={g} request={request} operation={op} state=3 errno=0 status=0x00 opcode=0x{detail} profile=1')
                    request += 1
                sequence[rx] = sequence.get(rx,0) + 1
                seq = sequence[rx]
                out.append(f'NativeDiscoveryMatch: generation={rx} seq={seq} address=02:73:00:00:00:0{tx} RSSI=-42 marker={marker} data={data} kernel_boottime_ns={seq*1000} elapsed_ms=500 lost=0')
                out.append(f'DAEMON_RADIO_ROUND: phase={phase} round={n} tx={tx_path} rx={rx_path} marker={marker}')
                for op,g,opcode in [(2,tx,'0c05'),(4,rx,'1002')]:
                    out.append(f'NativeOperationResult: generation={g} request={request} operation={op} state=3 errno=0 status=0x00 opcode=0x{opcode} step=0/1 power=0 power_valid=0 adv=1 scan=1 profile=1')
                    request += 1
            out.append(f'DAEMON_RADIO_NEGATIVE: phase={phase} no_new_report=1 duration_ms=2000')
        out.append('DAEMON_HOTPLUG: independent=2 same_process=1 new_generation=1')
        cls.good = '\n'.join(out) + '\n'

    def test_complete(self): self.assertEqual(assess_radio(self.good), [])
    def test_wrong_address(self): self.assertTrue(assess_radio(self.good.replace('address=02:73:00:00:00:01', 'address=02:73:00:00:00:02',1)))
    def test_wrong_generation(self): self.assertTrue(assess_radio(self.good.replace('generation=2 seq=', 'generation=1 seq=',1)))
    def test_timeout(self): self.assertTrue(assess_radio(self.good.replace('elapsed_ms=500', 'elapsed_ms=10000',1)))
    def test_loss(self): self.assertTrue(assess_radio(self.good.replace('lost=0', 'lost=1',1)))
    def test_zero_kernel_timestamp(self): self.assertTrue(assess_radio(self.good.replace('kernel_boottime_ns=1000', 'kernel_boottime_ns=0',1)))
    def test_stale_sequence(self): self.assertTrue(assess_radio(self.good.replace('seq=2 ', 'seq=1 ',1)))
    def test_missing_negative(self): self.assertTrue(assess_radio(self.good.replace('no_new_report=1', 'no_new_report=0',1)))
    def test_failed_complete(self): self.assertTrue(assess_radio(self.good.replace('state=3 errno=0 status=0x00', 'state=4 errno=0 status=0xfd',1)))
    def test_duplicate_result(self): self.assertTrue(assess_radio(self.good + next(line for line in self.good.splitlines() if line.startswith('NativeOperationResult:')) + '\n'))
    def test_wrong_admission(self): self.assertTrue(assess_radio(self.good.replace('Accepted: request=100', 'Accepted: request=99',1)))
    def test_radio_before_ready(self): self.assertTrue(assess_radio(self.good.replace('DAEMON_ADD_SECOND','missing',1)))
    def test_runtime_panic(self): self.assertTrue(assess(GOOD + "thread 'executor' panicked at radio.rs:1\n",0))


if __name__ == '__main__': unittest.main()
