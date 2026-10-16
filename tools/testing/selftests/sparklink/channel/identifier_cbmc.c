// SPDX-License-Identifier: GPL-2.0-only
/* Calls actual production codec. Valid C pointers/arrays; no kernel/USB model. */
#include <assert.h>
#include "../../../../../net/sparklink/sle_channel_wire.h"
extern unsigned char nondet_byte(void);
extern unsigned int nondet_uint(void);
int main(void)
{
    unsigned char bytes[16];
    unsigned int code=77,id=88,mask=99;
    struct sl_channel_cap cap={11,22,33,44};
    unsigned char identifier=nondet_byte();
    int n=sl_channel_cap_request(bytes,sizeof(bytes),identifier);
    assert(n==8);
    if(n!=8)return 0; /* counterexample must not call decode with an invalid length */
    assert(!sl_channel_cap_decode(bytes,n,&code,&id,&mask,&cap));
    assert(code==1 && id==identifier && mask==SL_CHANNEL_CAP_QUERY);
    n=sl_channel_cap_response(bytes,sizeof(bytes),identifier,mask,2042);
    assert(n==16);
    if(n!=16)return 0;
    assert(!sl_channel_cap_decode(bytes,n,&code,&id,&mask,&cap));
    assert(code==2 && id==identifier && cap.mtu==2042 && cap.mps==2042 && cap.modes==0);
    for(unsigned int i=0;i<sizeof(bytes);i++)bytes[i]=nondet_byte();
    code=77;id=88;mask=99;cap=(struct sl_channel_cap){11,22,33,44};
    unsigned int length=nondet_uint()%17;
    int ret=sl_channel_cap_decode(bytes,length,&code,&id,&mask,&cap);
    if(ret)assert(code==77 && id==88 && mask==99 && cap.mtu==11 && cap.mps==22 && cap.version==33 && cap.modes==44);
    else assert(id==bytes[1] && (code==1 || code==2));
}
