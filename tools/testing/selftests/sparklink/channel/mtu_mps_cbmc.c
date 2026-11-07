// SPDX-License-Identifier: GPL-2.0-only
/* Actual production transitions/codec; sequential C, not kernel refinement. */
#include <assert.h>
#include "../../../../../net/sparklink/sle_channel_state.h"
#include "../../../../../net/sparklink/sle_channel_wire.h"
extern unsigned int nondet_uint(void);
extern unsigned char nondet_byte(void);
int main(void)
{
    struct sl_channel_progress arbitrary = {.mtu=nondet_uint(), .mps=nondet_uint()};
    unsigned int tcid=nondet_uint(), header=tcid<=0x1d ? 4 : 5;
    unsigned int limit=sl_channel_payload_limit(arbitrary,tcid);
    assert(limit<=arbitrary.mtu);
    if(tcid && tcid<=255 && arbitrary.mps>header)
        assert(limit+header<=arbitrary.mps);
    else assert(limit==0);

    struct sl_channel_progress s={0};
    sl_channel_start(&s,2042,2047);
    for(unsigned int step=0;step<6;step++) {
        struct sl_channel_progress before=s;
        unsigned int event=nondet_uint()%7;
        int expired=nondet_uint()%2;
        switch(event) {
        case 0:sl_channel_request_submitted(&s,expired);break;
        case 1:sl_channel_peer_capability(&s,nondet_uint(),nondet_uint(),expired);break;
        case 2:sl_channel_response_submitted(&s,expired);break;
        case 3:sl_channel_tick(&s,expired);break;
        case 4:sl_channel_close(&s);break;
        case 5:sl_channel_fail(&s);break;
        default:sl_channel_start(&s,nondet_uint(),nondet_uint());break;
        }
        assert(s.phase!=SL_CH_OPEN || (s.request_submitted && s.peer_capability && s.response_submitted));
        assert(s.phase!=SL_CH_OPEN || (s.mtu && s.mtu<=s.maximum && s.maximum<=2042));
        assert(s.phase!=SL_CH_OPEN || (s.mps>=20 && s.mps<=s.maximum_mps && s.maximum_mps<=2047));
        assert(before.phase!=SL_CH_FAILED || s.phase==SL_CH_FAILED || s.phase==SL_CH_CLOSED);
        assert(before.phase!=SL_CH_CLOSED || s.phase==SL_CH_CLOSED);
        assert(before.phase!=SL_CH_OPEN || s.phase!=SL_CH_OPEN || (s.mtu==before.mtu && s.mps==before.mps));
        assert(before.phase!=SL_CH_NEGOTIATING || !expired || event>3 || s.phase==SL_CH_FAILED);
    }
    unsigned char bytes[16];
    unsigned int mtu=1+nondet_uint()%2042,mps=20+nondet_uint()%2028;
    unsigned int code=0,id=0,mask=0;
    struct sl_channel_cap cap={0};
    int n=sl_channel_cap_response(bytes,sizeof(bytes),nondet_byte(),SL_CHANNEL_CAP_QUERY,mtu,mps);
    assert(n==16);
    if(n!=16)return 0;
    assert(!sl_channel_cap_decode(bytes,n,&code,&id,&mask,&cap));
    assert(cap.mtu==mtu && cap.mps==mps);
}
