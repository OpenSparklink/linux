/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_FRAGMENT_CURSOR_H
#define _SLE_FRAGMENT_CURSOR_H
/* DLI PB fragments one DTAP PDU. Only the Session's serialized worker advances
 * this cursor after a successful joined transport call. EAGAIN leaves it intact;
 * uncertain failure retires the Session, never retries a submitted prefix.
 * One connection-wide cursor excludes CMTC/other channels until completion.
 */
#define SL_FRAGMENT_PDU_MAX 2047U
struct sl_fragment_cursor { unsigned int offset; unsigned long deadline; };
static inline int sl_fragment_next(unsigned int total, unsigned int offset,
    unsigned int maximum, unsigned int *length, unsigned int *boundary)
{
    unsigned int remaining;
    if (!total || total > SL_FRAGMENT_PDU_MAX || offset >= total ||
        !maximum || maximum > SL_FRAGMENT_PDU_MAX)
        return 0;
    remaining = total - offset;
    *length = remaining < maximum ? remaining : maximum;
    *boundary = offset ? (remaining > maximum ? 2 : 3) :
        (remaining > maximum ? 1 : 0);
    return 1;
}
static inline int sl_fragment_advance(struct sl_fragment_cursor *cursor,
    unsigned int total, unsigned int length)
{
    if (!total || total > SL_FRAGMENT_PDU_MAX || !length ||
        cursor->offset >= total || length > total - cursor->offset)
        return 0;
    cursor->offset += length;
    return 1;
}
#endif
