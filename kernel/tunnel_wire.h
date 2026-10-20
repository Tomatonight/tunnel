/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TUNNEL_WIRE_H
#define TUNNEL_WIRE_H

#include <linux/types.h>
#include <linux/string.h>

#define TK_RECORD_HEADER 32
#define TK_RECORD_OVERHEAD 48
#define TK_FORWARD_HEADER 70
#define TK_FORWARD_AAD 68
#define TK_HOP_LIMIT 32

static inline u16 tw_get16(const u8 *p)
{
	return ((u16)p[0] << 8) | p[1];
}
static inline u64 tw_get64(const u8 *p)
{
	u64 n = 0;
	unsigned int i;
	for (i = 0; i != 8; ++i)
		n = (n << 8) | p[i];
	return n;
}
static inline void tw_put16(u8 *p, u16 n)
{
	p[0] = n >> 8; p[1] = n;
}
static inline void tw_put64(u8 *p, u64 n)
{
	int i;
	for (i = 7; i >= 0; --i) { p[i] = n; n >>= 8; }
}
static inline u64 tnlk_hash_byte(u64 hash, u8 byte)
{
	return (hash ^ byte) * 1099511628211ULL;
}

#endif
