/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include "../../../../net/sparklink/sle_fragment_cursor.h"
unsigned int nondet_uint(void);
int main(void)
{
    unsigned int total=nondet_uint(), offset=nondet_uint(), maximum=nondet_uint();
    unsigned int length=0xfeed, boundary=0xface;
    struct sl_fragment_cursor cursor={.offset=offset, .deadline=123};
    int result=sl_fragment_next(total,offset,maximum,&length,&boundary);
    if (!result) {
        assert(length==0xfeed && boundary==0xface);
    } else {
        assert(total>0 && total<=2047 && maximum>0 && maximum<=2047);
        assert(offset<total && length>0 && length<=maximum && length<=total-offset);
        assert(boundary<=3);
        assert((offset==0 && length==total && boundary==0) ||
               (offset==0 && length<total && boundary==1) ||
               (offset>0 && length<total-offset && boundary==2) ||
               (offset>0 && length==total-offset && boundary==3));
        assert(sl_fragment_advance(&cursor,total,length));
        assert(cursor.offset==offset+length && cursor.offset<=total);
        assert(cursor.deadline==123);
    }
    cursor.offset=offset;
    unsigned int proposed=nondet_uint();
    result=sl_fragment_advance(&cursor,total,proposed);
    assert(cursor.deadline==123);
    if (!result) assert(cursor.offset==offset);
    else assert(cursor.offset>offset && cursor.offset<=total && total<=2047);
}
