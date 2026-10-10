/* SPDX-License-Identifier: GPL-2.0-only */
/* Compile actual legacy USB send body; only USB/allocation dependencies mocked. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
#define GFP_KERNEL 0
/* @@DEFINES@@ */
struct sle_usb_dev { bool active; void *udev; unsigned int ep_bulk_out; };
static struct sle_usb_dev usb_dev_table[SLE_USB_MAX_DEVS];
static int allocation_failure, transport_error, completed_length, calls, allocations;
static u8 frame[516];
static int frame_len;
static void *kmalloc(int n, int flags) { (void)flags;if(allocation_failure)return NULL;void *p=malloc((size_t)n);if(p)allocations++;return p; }
static void kfree(void *p) {if(p)allocations--;free(p);}
static unsigned int usb_sndbulkpipe(void *d, unsigned int ep) {assert(d==&usb_dev_table);return ep;}
static int usb_bulk_msg(void *d,unsigned int pipe,void *p,int n,int *actual,int timeout) {assert(d==&usb_dev_table && pipe==5 && timeout==SLE_CMD_TIMEOUT_MS);calls++;assert(n<=516);frame_len=n;memcpy(frame,p,(size_t)n);*actual=completed_length<0?n:completed_length;return transport_error;}
/* @@USB_FUNCTION@@ */
int main(void) {
 u8 payload[512];memset(payload,0xa5,sizeof(payload));usb_dev_table[0]=(struct sle_usb_dev){true,&usb_dev_table,5};completed_length=-1;
 assert(sle_usb_dev_send_data(-1,42,payload,4)==-EINVAL);
 assert(sle_usb_dev_send_data(SLE_USB_MAX_DEVS,42,payload,4)==-EINVAL);
 assert(sle_usb_dev_send_data(1,42,payload,4)==-ENODEV);
 assert(sle_usb_dev_send_data(0,42,payload,-1)==-EINVAL);
 assert(sle_usb_dev_send_data(0,42,payload,0)==-EINVAL);
 assert(sle_usb_dev_send_data(0,42,NULL,4)==-EINVAL);
 assert(sle_usb_dev_send_data(0,0x1000,payload,4)==-EINVAL);
 assert(sle_usb_dev_send_data(0,42,payload,512)==-EMSGSIZE && calls==0);
 allocation_failure=1;assert(sle_usb_dev_send_data(0,42,payload,4)==-ENOMEM && calls==0);allocation_failure=0;
 transport_error=-ETIMEDOUT;assert(sle_usb_dev_send_data(0,42,payload,4)==-ETIMEDOUT && allocations==0);transport_error=0;
 for(int n=0;n<9;n++) {completed_length=n;assert(sle_usb_dev_send_data(0,42,payload,4)==-EIO && allocations==0);}
 completed_length=10;assert(sle_usb_dev_send_data(0,42,payload,4)==-EIO && allocations==0);
 completed_length=-1;assert(sle_usb_dev_send_data(0,0x123,payload,4)==0 && frame_len==9 && allocations==0);
 assert(frame[0]==DLI_PKT_ASYNC_DATA && frame[1]==0x30 && frame[2]==0x12 && frame[3]==4 && frame[4]==0 && !memcmp(frame+5,payload,4));
 assert(sle_usb_dev_send_data(0,0xfff,payload,511)==0 && frame_len==516 && allocations==0);
 puts("ACTUAL_USB_TX_BOUNDARY_PASS: range/allocation/errno/short/exact/max-length");return 0;
}
