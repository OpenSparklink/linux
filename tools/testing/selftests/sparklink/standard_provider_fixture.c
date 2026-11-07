/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual standard provider adapter; registration/USB primitives controlled. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <linux/sparklink_backend.h>
#define THIS_MODULE NULL
struct mutex { bool held; };
static void mutex_lock(struct mutex*m){assert(!m->held);m->held=true;}
static void mutex_unlock(struct mutex*m){assert(m->held);m->held=false;}
/* @@METADATA@@ */
struct sle_usb_dev { struct mutex io_lock;bool active,suspended;u16 id;u64 generation; };
static struct sle_usb_dev device;
static struct sle_usb_metadata metadata;
static int refs,event_ret,data_ret,send_ret,metadata_ret,register_ret,cases;
static int events,datas,stop_events,stop_datas,sends,registrations;
static bool event_live,data_live,bad_output;
static struct sparklink_backend_descriptor copied;
static struct sparklink_native_identity copied_reservation;
static void sle_usb_dev_get(void*p){assert(p==&device);refs++;}
static void sle_usb_dev_put(void*p){assert(p==&device&&refs>0);refs--;}
static int sle_usb_dev_start_evt_locked(struct sle_usb_dev*d){assert(d==&device&&d->io_lock.held);events++;if(!event_ret)event_live=true;return event_ret;}
static int sle_usb_dev_start_data_locked(struct sle_usb_dev*d){assert(d==&device&&d->io_lock.held);datas++;if(!data_ret)data_live=true;return data_ret;}
static void sle_usb_dev_stop_evt_locked(struct sle_usb_dev*d){assert(d==&device&&d->io_lock.held);stop_events++;event_live=false;}
static void sle_usb_dev_stop_data_locked(struct sle_usb_dev*d){assert(d==&device&&d->io_lock.held);stop_datas++;data_live=false;}
static int sle_usb_dev_send_cmd(void*d,u16 op,const u8*p,int n){assert(d==&device&&op==0x0406&&p&&n==1);sends++;return send_ret;}
static int sle_usb_dev_get_metadata(struct sle_usb_dev*d,struct sle_usb_metadata*out){assert(d==&device);if(!metadata_ret)*out=metadata;return metadata_ret;}
int sparklink_backend_register_reserved(const struct sparklink_backend_descriptor*d,const struct sparklink_native_identity*reserved,struct sparklink_native_identity*out){assert(!sparklink_backend_validate(d));registrations++;copied=*d;copied_reservation=*reserved;if(register_ret)return register_ret;*out=*reserved;if(bad_output)out->generation++;return 0;}
/* @@ADAPTER@@ */
static void reset(void){refs=event_ret=data_ret=send_ret=metadata_ret=register_ret=events=datas=stop_events=stop_datas=sends=registrations=0;event_live=data_live=bad_output=false;device=(struct sle_usb_dev){.active=true,.id=3,.generation=99};metadata=(struct sle_usb_metadata){.capabilities={.command_max=65535,.acb_length=2047,.acb_count=5,.features={1,2,3,4,5,6,7,8,9,10}},.version={1,2,3,4,5},.address={1,2,3,4,5,6},.command_credits=2};}
int main(void){
 reset();assert(!sle_usb_dev_install_provider(&device)&&registrations==1);assert(copied.info.profile==0&&copied.capabilities==0&&copied.bus==1);assert(copied_reservation.id==3&&copied_reservation.generation==99);assert(!memcmp(copied.info.version,metadata.version,5)&&!memcmp(copied.info.features,metadata.capabilities.features,10)&&!memcmp(copied.info.address,metadata.address,6));assert(copied.info.acb_length==2047&&copied.info.acb_count==5&&copied.info.command_credits==2);assert(!copied.ops->prepare_discovery&&!copied.ops->prepare_connection&&!copied.ops->send_acb);cases++;
 reset();metadata_ret=-ENODATA;assert(sle_usb_dev_install_provider(&device)==-ENODATA&&!registrations);cases++;
 reset();register_ret=-ENOMEM;assert(sle_usb_dev_install_provider(&device)==-ENOMEM&&registrations==1);cases++;
 reset();bad_output=true;assert(sle_usb_dev_install_provider(&device)==-EPROTO);cases++;
 reset();sle_usb_provider_ops.get(&device);sle_usb_provider_ops.get(&device);assert(refs==2);sle_usb_provider_ops.put(&device);assert(refs==1);sle_usb_provider_ops.put(&device);assert(refs==0);cases++;
 reset();assert(!sle_usb_provider_ops.open(&device,3,99)&&event_live&&data_live&&events==1&&datas==1&&!device.io_lock.held);sle_usb_provider_ops.close(&device);assert(!event_live&&!data_live&&stop_events==1&&stop_datas==1&&!device.io_lock.held);cases++;
 reset();event_ret=-ENOMEM;assert(sle_usb_provider_ops.open(&device,3,99)==-ENOMEM&&events==1&&!datas&&!event_live&&!device.io_lock.held);cases++;
 reset();data_ret=-EIO;assert(sle_usb_provider_ops.open(&device,3,99)==-EIO&&events==1&&datas==1&&stop_events==1&&!event_live&&!data_live&&!device.io_lock.held);cases++;
 reset();assert(sle_usb_provider_ops.open(&device,4,99)==-ENODEV&&!events);assert(sle_usb_provider_ops.open(&device,3,98)==-ENODEV&&!events);cases++;
 reset();device.active=false;assert(sle_usb_provider_ops.open(&device,3,99)==-ENODEV&&!events);cases++;
 reset();device.suspended=true;assert(sle_usb_provider_ops.open(&device,3,99)==-EAGAIN&&!events);cases++;
 reset();for(u16 op=0x0401;op<=0x0404;op++){assert(!sle_usb_provider_ops.validate_command(&device,op,NULL,0));assert(sle_usb_provider_ops.validate_command(&device,op,(u8[]){0},1)==-EINVAL);}for(u8 type=0;type<8;type++){assert(sle_usb_provider_ops.validate_command(&device,0x0406,&type,1)==(type==1||type==7?-EINVAL:0));}assert(sle_usb_provider_ops.validate_command(&device,0x0406,NULL,1)==-EINVAL);cases++;
 reset();assert(sle_usb_provider_ops.send_command(&device,0x0c05,(u8[]){1},1)==-EOPNOTSUPP&&!sends);assert(sle_usb_provider_ops.send_command(&device,0x0406,(u8[]){1},1)==-EINVAL&&!sends);cases++;
 reset();send_ret=-ETIMEDOUT;assert(sle_usb_provider_ops.send_command(&device,0x0406,(u8[]){0},1)==-ETIMEDOUT&&sends==1);cases++;
 printf("{\"status\":\"ACTUAL_COMMON_STANDARD_PROVIDER_PASS\",\"cases\":%d}\n",cases);return 0;
}
