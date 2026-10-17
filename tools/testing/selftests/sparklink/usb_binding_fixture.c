/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual command writer/sync query; only USB/allocation dependencies replaced. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
typedef uint8_t u8;typedef uint16_t u16;
#define GFP_KERNEL 0
struct usb_device { int unused; };
struct sle_usb_dev { bool active;struct usb_device*udev;u8 command_request_type;u16 command_index;u8 ep_intr_in; };
/* @@DEFINES@@ */
static int allocs,live,fail_alloc,control_calls,interrupt_calls,cases;
static int control_result,interrupt_result,reply_length,expected_timeout,parameter_length;
static const u8*parameters;
static struct usb_device device;
static struct sle_usb_dev context;
static void*kmalloc(int n,int flags){(void)flags;allocs++;if(allocs==fail_alloc)return NULL;live++;return malloc((size_t)n);}
static void kfree(void*p){if(p){assert(live>0);live--;free(p);}}
static void put_unaligned_le16(u16 n,u8*p){p[0]=(u8)n;p[1]=(u8)(n>>8);}
static unsigned usb_sndctrlpipe(struct usb_device*d,int ep){assert(d==&device&&ep==0);return 0;}
static unsigned usb_rcvintpipe(struct usb_device*d,int ep){assert(d==&device&&ep==0x91);return 1;}
static int usb_control_msg(struct usb_device*d,unsigned pipe,u8 request,u8 type,u16 value,u16 index,void*raw,u16 size,int timeout){
 assert(d==&device&&pipe==0&&request==0&&value==0&&type==context.command_request_type&&index==context.command_index&&timeout==expected_timeout);
 const u8*p=raw;assert(size==4+parameter_length&&p[0]==3&&p[1]==4&&p[2]==(u8)parameter_length&&p[3]==(u8)(parameter_length>>8));if(parameter_length)assert(!memcmp(p+4,parameters,(size_t)parameter_length));control_calls++;return control_result;
}
static int usb_interrupt_msg(struct usb_device*d,unsigned pipe,void*data,int capacity,int*actual,int timeout){
 assert(d==&device&&pipe==1&&capacity==64&&timeout==SLE_INIT_TIMEOUT_MS);memset(data,0x5a,(size_t)capacity);interrupt_calls++;*actual=reply_length;return interrupt_result;
}
/* @@WRITE@@ */
/* @@SEND@@ */
/* @@SYNC@@ */
/* @@DATA@@ */
static void reset(void){assert(live==0);allocs=fail_alloc=control_calls=interrupt_calls=parameter_length=interrupt_result=0;control_result=4;reply_length=18;expected_timeout=SLE_INIT_TIMEOUT_MS;parameters=NULL;context=(struct sle_usb_dev){.active=true,.udev=&device,.command_request_type=0x21,.command_index=2,.ep_intr_in=0x91};}
int main(void){
 u8 payload[65531],out[64];int length;for(int i=0;i<65531;i++)payload[i]=(u8)i;
 for(int recipient=0;recipient<2;recipient++){reset();context.command_request_type=recipient?0x21:0x20;context.command_index=recipient?2:0;assert(!sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)&&length==18&&out[0]==0x5a&&control_calls==1&&interrupt_calls==1);cases++;}
 int sizes[]={1,255,256,65531};for(int i=0;i<4;i++){reset();parameter_length=sizes[i];parameters=payload;control_result=4+parameter_length;assert(!sle_usb_send_cmd_sync(&context,0x0403,payload,parameter_length,out,64,&length));cases++;}
 int invalid[]={65532,65535,65536};for(int i=0;i<3;i++){reset();assert(sle_usb_send_cmd_sync(&context,0x0403,payload,invalid[i],out,64,&length)==-EMSGSIZE&&allocs==0&&control_calls==0&&interrupt_calls==0);cases++;}
 reset();assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,1,out,64,&length)==-EINVAL&&!allocs);cases++;
 reset();assert(sle_usb_send_cmd_sync(&context,0x0403,payload,-1,out,64,&length)==-EINVAL&&!allocs);cases++;
 for(int n=0;n<4;n++){reset();control_result=n;assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)==-EREMOTEIO&&control_calls==1&&interrupt_calls==0);cases++;}
 reset();control_result=-ETIMEDOUT;assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)==-ETIMEDOUT&&interrupt_calls==0);cases++;
 reset();interrupt_result=-ETIMEDOUT;assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)==-ETIMEDOUT&&control_calls==1);cases++;
 for(int i=1;i<=2;i++){reset();fail_alloc=i;assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)==-ENOMEM);assert(control_calls==i-1&&interrupt_calls==0);cases++;}
 for(int i=0;i<2;i++){reset();memset(out,7,64);reply_length=i?65:-1;assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)==-EPROTO&&out[0]==7);cases++;}
 reset();context.active=false;assert(sle_usb_send_cmd_sync(&context,0x0403,NULL,0,out,64,&length)==-ENODEV&&!allocs);cases++;
 reset();expected_timeout=SLE_CMD_TIMEOUT_MS;assert(!sle_usb_dev_send_cmd_locked(&context,0x0403,NULL,0)&&interrupt_calls==0);cases++;
 reset();assert(sle_usb_dev_send_cmd_locked(&context,0x0403,payload,256)==-EMSGSIZE&&!allocs&&!control_calls);cases++;
 reset();assert(sle_usb_dev_send_data_locked(&context,1,payload,1)==-EOPNOTSUPP&&!allocs&&!control_calls);context.active=false;assert(sle_usb_dev_send_data_locked(&context,1,payload,1)==-ENODEV);cases++;
 assert(live==0);printf("{\"status\":\"ACTUAL_STANDARD_USB_BINDING_PASS\",\"cases\":%d}\n",cases);return 0;
}
