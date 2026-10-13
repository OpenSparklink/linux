// SPDX-License-Identifier: GPL-2.0-only
// Actual downloader/sync/validator; USB, allocation and logging dependencies only.
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
#define GFP_KERNEL 0
#define min(a,b) ((a)<(b)?(a):(b))
#define pr_err(...) ((void)0)
#define pr_info(...) (success_logs++)
struct usb_device { int unused; };
struct sle_usb_dev { int active; struct usb_device *udev; int ep_bulk_in_size, ep_bulk_out, ep_bulk_in; };
/* @@DEFINES@@ */
static struct sle_usb_dev device_context;
static struct usb_device device;
static int success_logs, allocs, live_allocs, fail_alloc, start_ret;
static int chunks, done_out, reads, short_chunk, chunk_ret, done_ret, in_ret;
static int out_length, in_length, ack_kind, starts, cases, expected_offset;
static const u8 *firmware;
static void *kmalloc(int size,int flags) {
 (void)flags; allocs++; if(allocs==fail_alloc) return NULL;
 void *p=malloc((size_t)size); assert(p); live_allocs++; return p;
}
static void kfree(void *p) { if(p) { live_allocs--; free(p); } }
static unsigned int usb_sndbulkpipe(struct usb_device *d,int ep) { assert(d==&device); return (unsigned)ep; }
static unsigned int usb_rcvbulkpipe(struct usb_device *d,int ep) { assert(d==&device); return (unsigned)ep; }
static u16 get_unaligned_le16(const u8 *p) { return (u16)(p[0]|((u16)p[1]<<8)); }
static int sle_usb_dev_send_cmd_locked(struct sle_usb_dev*d,int opcode,u8 *params,int len) {
 assert(d==&device_context && opcode==SLE_OP_FW_DL_START && len==4);
 assert((params[0]|params[1]|params[2]|params[3])!=0); starts++; return start_ret;
}
static int usb_bulk_msg(struct usb_device *d,unsigned int pipe,u8 *data,int size,int *actual,int timeout) {
 assert(d==&device);
 if(pipe==2 && data[0]==SLE_FW_DATA_MARKER) {
  assert(timeout==SLE_FW_DL_TIMEOUT_MS && size>=SLE_FW_CHUNK_HDR);
  int offset=(int)((uint32_t)data[1]|((uint32_t)data[2]<<8)|((uint32_t)data[3]<<16)|((uint32_t)data[4]<<24));
  int len=data[5]|(data[6]<<8);
  assert(offset==expected_offset && size==len+SLE_FW_CHUNK_HDR);
  assert(memcmp(data+SLE_FW_CHUNK_HDR,firmware+offset,(size_t)len)==0);
  expected_offset+=len; chunks++; *actual=size-(short_chunk==chunks);
  return chunk_ret;
 }
 assert(timeout==SLE_INIT_TIMEOUT_MS);
 if(pipe==2) {
  assert(size==5 && data[0]==DLI_PKT_COMMAND && get_unaligned_le16(data+1)==SLE_OP_FW_DL_DONE);
  assert(data[3]==0 && data[4]==0); done_out++; *actual=out_length; return done_ret;
 }
 assert(pipe==1 && size==32); reads++; memset(data,0,(size_t)size);
 data[0]=SLE_EVT_CMD_COMPLETE; data[2]=4; data[4]=(u8)SLE_OP_FW_DL_DONE;
 data[5]=(u8)(SLE_OP_FW_DL_DONE>>8); data[6]=1;
 if(ack_kind==1)data[0]^=1;
 if(ack_kind==2)data[2]^=1;
 if(ack_kind==3)data[4]^=1;
 if(ack_kind==4)data[7]=1;
 *actual=in_length; return in_ret;
}
/* @@SYNC@@ */
/* @@VALIDATOR@@ */
/* @@DOWNLOAD@@ */
static void reset(const u8 *data) {
 assert(live_allocs==0); firmware=data;
 success_logs=allocs=fail_alloc=start_ret=chunks=done_out=reads=short_chunk=0;
 chunk_ret=done_ret=in_ret=ack_kind=starts=expected_offset=0;
 out_length=5; in_length=8;
 device_context=(struct sle_usb_dev){.active=1,.udev=&device,.ep_bulk_in_size=64,.ep_bulk_out=2,.ep_bulk_in=1};
}
static void check(int got,int expected) {
 assert(got==expected && live_allocs==0);
 assert(success_logs==(expected==0)); cases++;
}
int main(void) {
 u8 *data=malloc(SLE_FW_MAX_SIZE); assert(data);
 for(int i=0;i<SLE_FW_MAX_SIZE;i++)data[i]=(u8)(i^0x69);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),0);assert(chunks==2 && done_out==1 && reads==1);
 for(int n=1;n<=2;n++) {reset(data);short_chunk=n;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-EIO);assert(chunks==n && done_out==0 && reads==0);}
 reset(data);chunk_ret=-ETIMEDOUT;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-ETIMEDOUT);assert(chunks==1 && done_out==0);
 reset(data);start_ret=-ENODEV;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-ENODEV);assert(starts==1 && chunks==0);
 for(int n=1;n<=3;n++) {reset(data);fail_alloc=n;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-ENOMEM);}
 for(int n=1;n<=4;n++) {reset(data);ack_kind=n;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),n==4?-EREMOTEIO:-EPROTO);assert(reads==1);}
 for(int n=-1;n<=33;n++) {if(n==8)continue;reset(data);in_length=n;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-EPROTO);}
 for(int n=0;n<=6;n++) {if(n==5)continue;reset(data);out_length=n;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-EIO);assert(reads==0);}
 reset(data);done_ret=-EPIPE;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-EPIPE);assert(reads==0);
 reset(data);in_ret=-ETIMEDOUT;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-ETIMEDOUT);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,NULL,16,8),-EINVAL);assert(allocs==0);
 for(int n=-1;n<=0;n++){reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,n,8),-EINVAL);assert(allocs==0);}
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,SLE_FW_MAX_SIZE+1,8),-EFBIG);assert(allocs==0);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,16,-1),-EINVAL);assert(allocs==0);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,16,65536),-EMSGSIZE);assert(allocs==0);
 reset(data);device_context.ep_bulk_in_size=100000;check(sle_usb_dev_download_fw_locked(&device_context,data,16,0),-EMSGSIZE);assert(allocs==0);
 reset(data);device_context.active=0;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-ENODEV);assert(allocs==0);
 reset(data);device_context.udev=NULL;check(sle_usb_dev_download_fw_locked(&device_context,data,16,8),-ENODEV);assert(allocs==0);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,65536,65535),0);assert(chunks==2 && expected_offset==65536);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,SLE_FW_MAX_SIZE,65535),0);assert(expected_offset==SLE_FW_MAX_SIZE);
 reset(data);check(sle_usb_dev_download_fw_locked(&device_context,data,58,0),0);assert(chunks==2);
 reset(data);device_context.ep_bulk_in_size=7;check(sle_usb_dev_download_fw_locked(&device_context,data,241,0),0);assert(chunks==2);
 free(data);printf("{\"c_cases\":%d,\"status\":\"PASS_ACTUAL_FW_C_BOUNDARIES\"}\n",cases);return 0;
}
