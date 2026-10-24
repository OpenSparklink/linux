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
/* @@CAPABILITIES@@ */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
struct sle_usb_dev{bool active,metadata_valid;struct usb_device*udev;struct mutex io_lock;u8 version[5],mac_addr[6],command_credits;u32 fw_version;struct sle_usb_capabilities capabilities;};
static u16 get_unaligned_le16(const u8*p){return p[0]|(u16)p[1]<<8;}
static u32 get_unaligned_le32(const u8*p){return p[0]|(u32)p[1]<<8|(u32)p[2]<<16|(u32)p[3]<<24;}
static void*memchr_inv(const void*p,int c,unsigned n){const u8*b=p;for(unsigned i=0;i<n;i++)if(b[i]!=(u8)c)return(void*)(b+i);return NULL;}
#define pr_info(...) ((void)0)
/* @@DEFINES@@ */
static unsigned calls,fail_step,bad_step,zero_step,cases;
static int fail_code,malformation;
static int sle_usb_send_cmd_sync(struct sle_usb_dev*d,u16 op,const u8*params,int plen,u8*r,int capacity,int*len){
 assert(d->active&&d->udev&&capacity>=18);calls++;
 assert(plen==(op==SLE_OP_READ_MAC_ADDR?1:0));assert(!plen||(params&&params[0]==0));
 if(calls==fail_step)return fail_code;
 memset(r,0,(unsigned)capacity);r[0]=SLE_EVT_CMD_COMPLETE;r[4]=(u8)op;r[5]=(u8)(op>>8);r[6]=calls==zero_step?0:2;
 int n=0;const u8 version[]={0x21,0x34,0x12,0xcd,0xab},address[]={1,2,3,4,5,6};
 if(op==SLE_OP_READ_LOCAL_VERSION){n=5;memcpy(r+8,version,5);}
 if(op==SLE_OP_READ_CMD_LENGTH){n=2;r[8]=0xff;r[9]=0xff;}
 if(op==SLE_OP_READ_BUFFER){n=6;r[8]=0xff;r[9]=7;r[10]=0xff;r[11]=1;r[13]=2;}
 if(op==SLE_OP_READ_FEATURES){n=10;for(int i=0;i<n;i++)r[8+i]=(u8)(i+1);}
 if(op==SLE_OP_READ_MAC_ADDR){n=6;memcpy(r+8,address,6);}
 r[2]=(u8)(4+n);*len=8+n;
 if(calls==bad_step){
  if(malformation==1)(*len)--;if(malformation==2)r[4]^=1;if(malformation==3)r[7]=1;
  if(malformation==4)memset(r+8,0,(unsigned)n);
  if(malformation==5)memset(r+8,0xff,(unsigned)n);
  if(malformation==6)r[9]=8;
  if(malformation==7)r[10]=0;
  if(malformation==8){r[11]=0;r[12]=8;}
  if(malformation==9)r[13]=0;
  if(malformation==10){r[8]=254;r[9]=0;}
  if(malformation==11){r[8]=255;r[9]=0;}
 }
 return 0;
}
/* @@VALIDATOR@@ */
/* @@INIT@@ */
/* @@GETTER@@ */

static struct usb_device usb;
static struct sle_usb_dev reset(void){calls=fail_step=bad_step=zero_step=0;fail_code=malformation=0;return(struct sle_usb_dev){.active=true,.udev=&usb,.metadata_valid=true,.version={9,9,9,9,9},.fw_version=99,.mac_addr={8,8,8,8,8,8},.command_credits=7};}
int main(void){
 assert(sizeof(struct sle_usb_metadata)==30&&_Alignof(struct sle_usb_metadata)==2);
 struct sle_usb_dev d=reset();assert(!sle_usb_dev_init_controller_locked(&d));assert(d.metadata_valid&&calls==6&&d.fw_version==0xcd123421&&d.command_credits==2);struct sle_usb_metadata out={0};assert(!sle_usb_dev_get_metadata(&d,&out));assert(!memcmp(out.version,(u8[]){0x21,0x34,0x12,0xcd,0xab},5));cases++;
 for(unsigned step=1;step<=6;step++){
  d=reset();fail_step=step;fail_code=-ETIMEDOUT;assert(sle_usb_dev_init_controller_locked(&d)==-ETIMEDOUT&&!d.metadata_valid&&calls==step);memset(&out,7,sizeof(out));struct sle_usb_metadata untouched=out;assert(sle_usb_dev_get_metadata(&d,&out)==-ENODATA&&!memcmp(&out,&untouched,sizeof(out)));assert(d.fw_version==99);cases++;
  for(int wrong=1;wrong<=3;wrong++){d=reset();bad_step=step;malformation=wrong;assert(sle_usb_dev_init_controller_locked(&d)==(wrong==3?-EREMOTEIO:-EPROTO)&&!d.metadata_valid&&calls==step);cases++;}
 }
 for(unsigned step=1;step<=5;step++){d=reset();zero_step=step;assert(sle_usb_dev_init_controller_locked(&d)==-EAGAIN&&!d.metadata_valid&&calls==step);cases++;}
 d=reset();bad_step=6;malformation=4;assert(sle_usb_dev_init_controller_locked(&d)==-EPROTO&&!d.metadata_valid);cases++;
 d=reset();bad_step=6;malformation=5;assert(sle_usb_dev_init_controller_locked(&d)==-EPROTO&&!d.metadata_valid);cases++;
 for(int m=6;m<=9;m++){d=reset();bad_step=4;malformation=m;assert(sle_usb_dev_init_controller_locked(&d)==-EPROTO&&!d.metadata_valid&&calls==4);cases++;}
 d=reset();bad_step=3;malformation=10;assert(sle_usb_dev_init_controller_locked(&d)==-EPROTO&&!d.metadata_valid&&calls==3);cases++;
 d=reset();bad_step=3;malformation=11;assert(!sle_usb_dev_init_controller_locked(&d)&&d.capabilities.command_max==255);cases++;
 d=reset();bad_step=4;malformation=4;assert(!sle_usb_dev_init_controller_locked(&d)&&!d.capabilities.acb_count&&!d.capabilities.icb_count);cases++;
 d=reset();zero_step=6;assert(!sle_usb_dev_init_controller_locked(&d)&&d.metadata_valid&&!d.command_credits);cases++;
 d=reset();assert(!sle_usb_dev_init_controller_locked(&d));struct sle_usb_metadata snapshot={0};assert(!sle_usb_dev_get_metadata(&d,&snapshot));assert(snapshot.capabilities.command_max==65535&&snapshot.capabilities.acb_length==2047&&snapshot.capabilities.acb_count==255&&snapshot.capabilities.icb_length==1&&snapshot.capabilities.icb_count==2&&snapshot.capabilities.features[9]==10);cases++;
 memset(&snapshot,7,sizeof(snapshot));struct sle_usb_metadata untouched=snapshot;d.metadata_valid=false;assert(sle_usb_dev_get_metadata(&d,&snapshot)==-ENODATA&&!memcmp(&snapshot,&untouched,sizeof(snapshot)));d.active=false;assert(sle_usb_dev_get_metadata(&d,&snapshot)==-ENODEV&&!memcmp(&snapshot,&untouched,sizeof(snapshot)));assert(sle_usb_dev_get_metadata(NULL,&snapshot)==-EINVAL&&sle_usb_dev_get_metadata(&d,NULL)==-EINVAL);cases++;
 d=reset();d.active=false;assert(sle_usb_dev_get_metadata(&d,&out)==-ENODEV);assert(sle_usb_dev_init_controller_locked(&d)==-ENODEV&&calls==0);cases++;
 assert(sle_usb_dev_get_metadata(NULL,&out)==-EINVAL);assert(sle_usb_dev_get_metadata(&d,NULL)==-EINVAL);cases++;
 printf("{\"status\":\"ACTUAL_USB_BOOTSTRAP_TUPLE_PASS\",\"cases\":%u}\n",cases);return 0;
}
