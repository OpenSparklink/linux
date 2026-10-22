// SPDX-License-Identifier: GPL-2.0-only
/* Explicit synthetic bytes, no firmware capability or RF qualification. */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "connection.h"
int main(void)
{
    struct sparklink_connection_parameters p = {.peer_address={0,1,9,0x32,0x54,0xf9},
        .gt_negotiate=1,.frame=1,.scan_interval=32,.scan_window=32,
        .interval_min=12,.interval_max=12,.supervision_timeout=508};
    struct sparklink_connection_request request = {.operation=1,.parameters=p};
    struct sparklink_connection_plan plan, unchanged;
    memset(&plan,0xaa,sizeof(plan));unchanged=plan;
    request.parameters.reserved[0]=1;
    assert(ws73_connection_prepare(&request,&plan)==-EINVAL);assert(!memcmp(&plan,&unchanged,sizeof(plan)));
    request.parameters.reserved[0]=0;
    assert(ws73_connection_prepare(&request,&plan)==0);assert(plan.operation==1&&plan.opcode==0x1401&&plan.length==27);
    assert(ws73_connection_validate(plan.operation,plan.opcode,plan.params,plan.length)==0);
    request.operation=2;memset(&request.parameters,0,sizeof(request.parameters));request.handle=0xffff;request.reason=0x13;
    assert(ws73_connection_prepare(&request,&plan)==0);assert(plan.operation==2&&plan.opcode==0x1403&&plan.length==3);
    assert(plan.params[0]==255&&plan.params[1]==255&&plan.params[2]==0x13);
    unchanged=plan;request.operation=3;
    assert(ws73_connection_prepare(&request,&plan)==-EOPNOTSUPP);assert(!memcmp(&plan,&unchanged,sizeof(plan)));
    const unsigned char expected[27]={0,0,0,0,1,9,0x32,0x54,0xf9,1,1,32,0,32,0,12,0,12,0,0,0,0xfc,1,0,0,0,0};
    unsigned char out[32], before[32]; memset(out,0xaa,sizeof(out));memcpy(before,out,sizeof(out));
    for (size_t n=0;n<27;n++) {assert(ws73_connection_create(out,n,&p)==-ENOSPC);assert(!memcmp(out,before,32));}
    assert(ws73_connection_create(out,32,&p)==27);assert(!memcmp(out,expected,27));assert(!memcmp(out+27,before+27,5));
    assert(ws73_connection_validate(1,0x1401,out,27)==0);
    assert(ws73_connection_validate(1,0x1401,out,6)==-EINVAL);
    assert(ws73_connection_validate(1,0x1401,out,31)==-EINVAL);
    assert(ws73_connection_validate(1,0x1403,out,27)==-EINVAL);
    for (unsigned int kind=0;kind<8;kind++) {
        struct sparklink_connection_parameters bad=p;
        switch(kind){case 0:bad.scan_window=33;break;case 1:bad.interval_min=13;break;
        case 2:bad.supervision_timeout=0;break;case 3:bad.frame=2;break;case 4:bad.gt_negotiate=4;break;
        case 5:bad.peer_address_type=256;break;case 6:bad.event_min=1;break;default:memset(bad.peer_address,0,6);}
        memcpy(out,before,32);assert(ws73_connection_create(out,32,&bad)==-EINVAL);assert(!memcmp(out,before,32));
    }
    for(unsigned int handle=0;handle<=65535;handle+=257){
        memcpy(out,before,32);assert(ws73_connection_disconnect(out,32,handle,0x13)==3);
        assert(out[0]==(handle&255)&&out[1]==(handle>>8)&&out[2]==0x13);
        assert(!memcmp(out+3,before+3,29));assert(ws73_connection_validate(2,0x1403,out,3)==0);
    }
    assert(ws73_connection_disconnect(out,32,65536,0x13)==-EINVAL);
    assert(ws73_connection_disconnect(out,32,7,256)==-EINVAL);
    assert(ws73_connection_validate(3,0x1402,NULL,0)==-EOPNOTSUPP); // cancel not qualified on v111
    assert(ws73_connection_validate(1,0x1401,NULL,27)==-EINVAL);
    for (unsigned int operation = 4; operation <= 5; operation++) {
        struct sparklink_connection_request q = {.operation=operation, .handle=0xabcd};
        assert(ws73_connection_prepare(&q,&plan)==0);
        assert(plan.operation==operation && plan.opcode==(operation==4?0x180c:0x1805) && plan.length==2);
        assert(plan.params[0]==0xcd && plan.params[1]==0xab);
        assert(ws73_connection_validate(operation,plan.opcode,plan.params,2)==0);
        assert(ws73_connection_validate(operation,plan.opcode,plan.params,1)==-EINVAL);
        assert(ws73_connection_validate(operation,plan.opcode,plan.params,3)==-EINVAL);
        assert(ws73_connection_validate(operation,plan.opcode^1,plan.params,2)==-EINVAL);
        assert(ws73_connection_validate(operation,plan.opcode,NULL,2)==-EINVAL);
        unchanged=plan;q.reason=1;
        assert(ws73_connection_prepare(&q,&plan)==-EINVAL && !memcmp(&plan,&unchanged,sizeof(plan)));
        q.reason=0;q.parameters.frame=1;
        assert(ws73_connection_prepare(&q,&plan)==-EINVAL && !memcmp(&plan,&unchanged,sizeof(plan)));
        q.parameters.frame=0;q.handle=65536;
        assert(ws73_connection_prepare(&q,&plan)==-EINVAL && !memcmp(&plan,&unchanged,sizeof(plan)));
    }
    const unsigned int octets[] = {1,254,1526,65535};
    for (unsigned int n=0;n<4;n++) {
        struct sparklink_connection_request q = {.operation=6,.handle=0xabcd,.payload_octets=octets[n]};
        assert(ws73_connection_prepare(&q,&plan)==0);
        assert(plan.operation==6 && plan.opcode==0x1804 && plan.length==4);
        assert(plan.params[0]==0xcd && plan.params[1]==0xab);
        assert(plan.params[2]==(octets[n]&255) && plan.params[3]==(octets[n]>>8));
        for (unsigned int size=0;size<=32;size++)
            assert(ws73_connection_validate(6,0x1804,plan.params,size)==(size==4?0:-EINVAL));
        assert(ws73_connection_validate(6,0x1804,NULL,4)==-EINVAL);
        assert(ws73_connection_validate(6,0x1805,plan.params,4)==-EINVAL);
        unchanged=plan;
        for (unsigned int bad=0;bad<6;bad++) {
            struct sparklink_connection_request r=q;
            switch(bad) { case 0:r.payload_octets=0;break;case 1:r.payload_octets=65536;break;
            case 2:r.reason=1;break;case 3:r.parameters.frame=1;break;case 4:r.handle=65536;break;default:r.operation=4; }
            assert(ws73_connection_prepare(&r,&plan)==-EINVAL && !memcmp(&plan,&unchanged,sizeof(plan)));
        }
    }
    puts("WS73_CONNECTION_PRODUCTION_CODEC: PASS; not running kernel or RF");return 0;
}
