/* adbuf.h - header file for adbuf.c
 *
 * Copyright(C) 2001-2002 Salvatore Sanfilippo <antirez@invece.org>
 * All rights reserved.
 * See the LICENSE file for COPYRIGHT and PERMISSION notice */

/* $Id: adbuf.h,v 1.1.1.1 2003/08/31 17:24:00 antirez Exp $ */

#ifndef _ADBUF_H
#define _ADBUF_H

#include <sys/types.h>

struct adbuf {
	char *buf;
	size_t size;	/* total buffer size */
	size_t left;	/* unused buffer size */
	/* the size of data stored is just size-left */
};

#define ADBUF_INCR	256	/* note that this MUST BE >= 1 */
#define adbuf_used(b)	((b)->size - (b)->left)
#define adbuf_ptr(b)	((b)->buf)

/* Rawly create an adbuf object. 's' is supposed to be some heap
 * memory already allocated, with some nul-term string inside */
#define adbuf_from_heapstring(b,s) \
	do { b->buf = s; b->left = 0; b->size = strlen(s); } while(0)

int adbuf_init(struct adbuf *b);
void adbuf_free(struct adbuf *b);
int adbuf_reset(struct adbuf *b);
int adbuf_add(struct adbuf *b, void *data, size_t len);
int adbuf_addchar(struct adbuf *b, int c);
int adbuf_strcat(struct adbuf *b, char *string);
int adbuf_cat(struct adbuf *a, struct adbuf *b);
int adbuf_cut(struct adbuf *b, size_t count);
int adbuf_ltrim(struct adbuf *b, size_t count);
int adbuf_rtrim(struct adbuf *b, size_t count);
int adbuf_add_long(struct adbuf *b, long l);
int adbuf_add_ulong(struct adbuf *b, unsigned long l);
int adbuf_clone(struct adbuf *src, struct adbuf *dst);
int adbuf_printf(struct adbuf *dst, const char *fmt, ...);

#endif /* _ADBUF_H */
