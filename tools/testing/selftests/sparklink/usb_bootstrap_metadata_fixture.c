/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;
struct mutex{int held;};
static void mutex_lock(struct mutex*m){assert(!m->held);m->held=1;}
static void mutex_unlock(struct mutex*m){assert(m->held);m->held=0;}
struct usb_device{int unused;};
struct sle_usb_dev{bool active,metadata_valid;struct usb_device*udev;struct mutex io_lock;u8 version[5],mac_addr[6],command_credits;u32 fw_version;};
static u16 get_unaligned_le16(const u8*p){return p[0]|(u16)p[1]<<8;}
static u32 get_unaligned_le32(const u8*p){return p[0]|(u32)p[1]<<8|(u32)p[2]<<16|(u32)p[3]<<24;}
static void*memchr_inv(const void*p,int c,unsigned n){const u8*b=p;for(unsigned i=0;i<n;i++)if(b[i]!=(u8)c)return(void*)(b+i);return NULL;}
#define pr_info(...) ((void)0)
/* @@DEFINES@@ */
static unsigned calls,fail_step,bad_step,zero_step,cases;
static int fail_code,malformation;
static int sle_usb_send_cmd_sync(struct sle_usb_dev*d,u16 op,u8*r,int capacity,int*len){
 assert(d->active&&d->udev&&capacity>=14);calls++;
 if(calls==fail_step)return fail_code;
 memset(r,0,(unsigned)capacity);r[0]=SLE_EVT_CMD_COMPLETE;r[4]=(u8)op;r[5]=(u8)(op>>8);r[6]=calls==zero_step?0:2;
 int n=op==SLE_OP_RESET?0:op==SLE_OP_READ_LOCAL_VERSION?5:6;r[2]=(u8)(4+n);*len=8+n;
 const u8 version[]={0x21,0x34,0x12,0xcd,0xab},address[]={1,2,3,4,5,6};
 memcpy(r+8,op==SLE_OP_READ_LOCAL_VERSION?version:address,(unsigned)n);
 if(calls==bad_step){if(malformation==1)(*len)--;if(malformation==2)r[4]^=1;if(malformation==3)r[7]=1;if(malformation==4&&op==SLE_OP_READ_MAC_ADDR)memset(r+8,0,6);}
 return 0;
}
/* @@VALIDATOR@@ */
/* @@INIT@@ */
/* @@GETTER@@ */
static struct usb_device usb;
static struct sle_usb_dev reset(void){calls=fail_step=bad_step=zero_step=0;fail_code=malformation=0;return(struct sle_usb_dev){.active=true,.udev=&usb,.metadata_valid=true,.version={9,9,9,9,9},.fw_version=99,.mac_addr={8,8,8,8,8,8},.command_credits=7};}
int main(void){
 struct sle_usb_dev d=reset();assert(!sle_usb_dev_init_controller_locked(&d));assert(d.metadata_valid&&calls==3&&d.fw_version==0xcd123421&&d.command_credits==2);u8 out[5]={0};assert(!sle_usb_dev_get_version(&d,out));assert(!memcmp(out,(u8[]){0x21,0x34,0x12,0xcd,0xab},5));cases++;
 for(unsigned step=1;step<=3;step++){
  d=reset();fail_step=step;fail_code=-ETIMEDOUT;assert(sle_usb_dev_init_controller_locked(&d)==-ETIMEDOUT&&!d.metadata_valid&&calls==step);memset(out,7,5);assert(sle_usb_dev_get_version(&d,out)==-ENODATA&&!memcmp(out,(u8[]){7,7,7,7,7},5));assert(d.fw_version==99);cases++;
  for(int wrong=1;wrong<=3;wrong++){d=reset();bad_step=step;malformation=wrong;assert(sle_usb_dev_init_controller_locked(&d)==(wrong==3?-EREMOTEIO:-EPROTO)&&!d.metadata_valid&&calls==step);cases++;}
 }
 for(unsigned step=1;step<=2;step++){d=reset();zero_step=step;assert(sle_usb_dev_init_controller_locked(&d)==-EAGAIN&&!d.metadata_valid&&calls==step);cases++;}
 d=reset();bad_step=3;malformation=4;assert(sle_usb_dev_init_controller_locked(&d)==-EPROTO&&!d.metadata_valid);cases++;
 d=reset();d.active=false;assert(sle_usb_dev_get_version(&d,out)==-ENODEV);assert(sle_usb_dev_init_controller_locked(&d)==-ENODEV&&calls==0);cases++;
 assert(sle_usb_dev_get_version(NULL,out)==-EINVAL);assert(sle_usb_dev_get_version(&d,NULL)==-EINVAL);cases++;
 printf("{\"status\":\"ACTUAL_USB_BOOTSTRAP_TUPLE_PASS\",\"cases\":%u}\n",cases);return 0;
}
