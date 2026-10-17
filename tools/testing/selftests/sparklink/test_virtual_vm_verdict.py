#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic transcript parser checks only; never kernel or RF qualification."""
import unittest
from run_virtual_vm import verify_console

class Verdict(unittest.TestCase):
    def test_required_fault_and_original_cases_reject_negative_controls(self):
        rows=[]
        for marker,count in [('VIRTUAL_RUNTIME_PASS:',2),('VIRTUAL_QUERY_RELEASE_PASS:',2),('VIRTUAL_STANDARD_SNOOP_PASS:',2),('VIRTUAL_DIAGNOSTIC_FD_PASS:',2),('PROTOCOL_STATE_REFUSAL_PASS:',4),('VIRTUAL_POWER_UNSUPPORTED_PASS:',4),('VIRTUAL_GLOBAL_POWER_POLICY_PASS:',2),('GENL_REGISTRY_PASS: uid=1000',2),('GENL_REGISTRY_PASS: uid=0',8)]:rows += [marker]*count
        hardware='VIRTUAL_HARDWARE_ERROR_PASS: id={} generation={} requests=2 submitted=1 late_reply=ignored callback_return=1 credit=0 inherited_CAP=EPERM invalid=EINVAL bad_pointer=EFAULT retired_status=ENOTTY peer=1 reuse=1 raw_code=7 no_rf=1'
        for identity,generation in [(2,7),(2,19)]:rows += [hardware.format(identity,generation),f'sle{identity} generation={generation} controller hardware error code=0x07; Host quarantined']
        rows+=['VIRTUAL_MODULE_ROUND_PASS:2','VIRTUAL_VM_PASS'];log='\n'.join(rows)
        verify_console(log,0)  # fixture grammar, explicitly not a live result
        for bad,code in [(log,1),(log.replace('VIRTUAL_HARDWARE_ERROR_PASS:','Missing:',1),0),(log.replace('raw_code=7','raw_code=8',1),0),(log.replace('generation=19','generation=7'),0),(log.replace('controller hardware error code=0x07','missing hardware observation',1),0),(log+'\nKernel panic',0),(log.replace('VIRTUAL_DIAGNOSTIC_FD_PASS:','Missing:',1),0)]:
            with self.subTest(code=code,tail=bad[-70:]),self.assertRaises((ValueError,RuntimeError)):verify_console(bad,code)

if __name__=='__main__':unittest.main()
