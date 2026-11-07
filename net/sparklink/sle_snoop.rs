// SPDX-License-Identifier: GPL-2.0
//! Bounded per-registration trace. No allocation or protocol admission in RX.
use kernel::prelude::*;
use super::{sle_dev::DeviceIdentity, sle_uapi::{SleSnoopRecord,SNOOP_PAYLOAD_MAX,SNOOP_TRUNCATED,SNOOP_REDACTED}};

const CAPACITY: usize = 64;
pub(crate) struct SnoopLog {
    records: [SleSnoopRecord; CAPACITY], count: usize, tail: usize, seq: u64,
}
impl SnoopLog {
    pub(crate) fn new_boxed() -> Result<KBox<Self>> {
        KBox::init(init!(Self {
            // SAFETY: integer-only representation has a valid zero baseline.
            records <- pin_init::init_array_from_fn(|_| unsafe { core::mem::zeroed::<SleSnoopRecord>() }),
            count:0, tail:0, seq:0,
        }),GFP_KERNEL)
    }
    pub(crate) fn current_seq(&self) -> u64 { self.seq }
    fn prepare(&mut self, identity: DeviceIdentity, profile:u32, direction:u8, status:i32, length:usize) -> Option<&mut SleSnoopRecord> {
        let seq=self.seq.checked_add(1)?;
        self.seq=seq;
        let record=&mut self.records[self.tail];
        self.tail=(self.tail+1)%CAPACITY; self.count=(self.count+1).min(CAPACITY);
        record.seq=seq; record.generation=identity.generation;
        // SAFETY: CLOCK_BOOTTIME may be read in USB completion context.
        record.timestamp_ns=unsafe { kernel::bindings::ktime_get_boottime() } as u64;
        record.lost=0; record.profile=profile; record.original_length=length.min(u32::MAX as usize) as u32;
        record.status=status; record.dev_index=identity.id; record.direction=direction; record.format=if profile==0 {2} else {1};
        record.captured_length=length.min(SNOOP_PAYLOAD_MAX) as u16;
        record.flags=if length>SNOOP_PAYLOAD_MAX {SNOOP_TRUNCATED} else {0};
        record.reserved=0; record.payload.fill(0);
        Some(record)
    }
    pub(crate) fn rx(&mut self, identity:DeviceIdentity, profile:u32, data:&[u8]) {
        if let Some(record)=self.prepare(identity,profile,1,0,data.len()) {
            let n=record.captured_length as usize; record.payload[..n].copy_from_slice(&data[..n]);
        }
    }
    /// These bytes are the same WS73 A1 framing encoded by the driver's wire
    /// codec. status is the actual blocking transport result, not DLI status.
    pub(crate) fn tx(&mut self, identity: DeviceIdentity, profile:u32, opcode:u16, params:&[u8], status:i32) {
        let header = if profile == 0 {4} else {5};
        if let Some(record)=self.prepare(identity,profile,2,status,params.len()+header) {
            let offset = if profile == 0 {0} else {record.payload[0]=0xa1; 1};
            record.payload[offset..offset+2].copy_from_slice(&opcode.to_le_bytes());
            record.payload[offset+2..offset+4].copy_from_slice(&(params.len() as u16).to_le_bytes());
            if profile==1 && matches!(opcode,0x1c03|0x1c05) {
                record.flags |= SNOOP_REDACTED;
                record.captured_length=header as u16;
                return;
            }
            let n=(record.captured_length as usize).saturating_sub(header);
            record.payload[header..header+n].copy_from_slice(&params[..n]);
        }
    }
    pub(crate) fn next_after(&self, after:u64) -> Option<SleSnoopRecord> {
        let oldest=(self.tail+CAPACITY-self.count)%CAPACITY;
        for n in 0..self.count {
            let record=&self.records[(oldest+n)%CAPACITY];
            if record.seq>after { let mut copy=*record; copy.lost=record.seq-after-1; return Some(copy); }
        }
        None
    }
}
