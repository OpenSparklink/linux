#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual retained parser and historical encoder bodies, allocation fixture only."""
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path

def function(text,name):
    start=text.index('pub fn '+name+'(');brace=text.index('{',start);end=brace+1;depth=1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]

def run(output):
    here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink'
    paths=[here/'retired-transport/uart_decoder.rs',net/'sle_dli.rs',here/'retired-transport/sle_uart.rs',here/'retired-transport/sle_spi.rs']
    contents={p:p.read_text() for p in paths}
    dli=contents[net/'sle_dli.rs'];a=dli.index('#[repr(u8)]',dli.index('/// DLI packet type'));b=dli.index('\n}',a)+2;enum=dli[a:b]
    encoder=function(contents[here/'retired-transport/sle_uart.rs'],'encode_command')
    spi=function(contents[here/'retired-transport/sle_spi.rs'],'encode_spi_command')+'\n'+function(contents[here/'retired-transport/sle_spi.rs'],'encode_spi_data_write')
    fixture='''extern crate self as kernel;
    pub mod alloc { pub struct KVec<T>(pub Vec<T>); impl<T> KVec<T> {
      pub fn new()->Self {Self(Vec::new())} pub fn clear(&mut self){self.0.clear()}
      pub fn push(&mut self,v:T,_flags:u32)->Result<(),std::collections::TryReserveError>{self.0.try_reserve(1)?;self.0.push(v);Ok(())}
    }}
    pub mod prelude {pub const GFP_KERNEL:u32=0;}
    mod sle_dli { ENUM }
    mod framing;
    use sle_dli::DliPacketType; const CMD_HEADER_SIZE:usize=5; const MAX_PAYLOAD_LEN:usize=255;
    const REG_CMD:u8=1;const REG_DATA_TX:u8=2;
    ENCODER
    SPI
    #[test] fn retained_uart_event_all_split_points(){
      let wire=[0xa2,0x34,0x12,3,0,1,2,3];
      for split in 0..=wire.len(){let mut p=framing::UartParser::new();let mut out=alloc::KVec::new();p.feed_bytes(&wire[..split],&mut out);p.feed_bytes(&wire[split..],&mut out);
        assert_eq!(out.0.len(),1);match &out.0[0]{framing::UartFrame::Event{event_code,params}=>{assert_eq!(*event_code,0x1234);assert_eq!(params.0,[1,2,3]);},_=>panic!("wrong frame")}}
    }
    #[test] fn historical_command_encoding_uses_actual_retained_parser(){
      let mut buf=[0u8;260];assert_eq!(encode_command(0x1234,&[1,2,3],&mut buf),8);assert_eq!(&buf[..8],&[0xa1,0x34,0x12,3,0,1,2,3]);
      let mut p=framing::UartParser::new();let mut out=alloc::KVec::new();p.feed_bytes(&buf[..8],&mut out);
      match &out.0[0]{framing::UartFrame::Command{opcode,params}=>{assert_eq!(*opcode,0x1234);assert_eq!(params.0,[1,2,3]);},_=>panic!("wrong frame")}
      assert_eq!(encode_command(1,&[0;256],&mut buf),0);
    }
    #[test] fn all_data_types_handles_flags_and_payload(){
      for kind in [0xa3,0xa4,0xa5]{let mut p=framing::UartParser::new();let mut out=alloc::KVec::new();p.feed_bytes(&[kind,0x34,0x12,1,0,99],&mut out);
        match &out.0[0]{framing::UartFrame::Data{pkt_type,handle,flags,payload}=>{assert_eq!(*pkt_type as u8,kind);assert_eq!(*handle,0x234);assert_eq!(*flags,1);assert_eq!(payload.0,[99]);},_=>panic!("wrong frame")}}
    }
    #[test] fn oversize_and_partial_never_publish_then_reset(){
      let mut p=framing::UartParser::new();let mut out=alloc::KVec::new();p.feed_bytes(&[0xa2,1,0,0,1],&mut out);assert!(out.0.is_empty());
      p.feed_bytes(&[0xa2,1,0,2,0,7],&mut out);assert!(out.0.is_empty());p.reset();p.feed_bytes(&[0xa2,2,0,0,0],&mut out);assert_eq!(out.0.len(),1);
      match &out.0[0]{framing::UartFrame::Event{event_code,params}=>{assert_eq!(*event_code,2);assert!(params.0.is_empty());},_=>panic!("wrong frame")}
    }
    #[test] fn historical_spi_register_bytes_and_bounds(){
      let mut buf=[0u8;260];assert_eq!(encode_spi_command(0x1234,3,&mut buf),6);assert_eq!(&buf[..6],&[1,0xa1,0x34,0x12,3,0]);assert_eq!(encode_spi_command(1,0,&mut buf[..5]),0);
      assert_eq!(encode_spi_data_write(&[7,8],&mut buf),3);assert_eq!(&buf[..3],&[2,7,8]);assert_eq!(encode_spi_data_write(&[0;256],&mut buf),0);
    }
    '''.replace('ENUM',enum).replace('ENCODER',encoder).replace('SPI',spi)
    with tempfile.TemporaryDirectory(prefix='sparklink-retired-transport-') as temp:
        t=Path(temp);(t/'framing.rs').write_text(contents[here/'retired-transport/uart_decoder.rs']);(t/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(t/'fixture.rs'),'-o',str(t/'test')],check=True)
        subprocess.run([str(t/'test')],check=True)
    assert all(p.read_text()==s for p,s in contents.items())
    result=dict(status='RETAINED_AND_HISTORICAL_TRANSPORT_CODEC_PASS',tests=5,sources={str(p):hashlib.sha256(s.encode()).hexdigest() for p,s in contents.items()},scope='actual retained UART parser; archived UART/SPI encoder bodies; Vec allocation dependency fixture; no hardware/serdev/SPI standard interoperability or allocation-failure qualification')
    if output:output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);run(p.parse_args().output)
