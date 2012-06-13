/* adbuf.c - dynamic buffers support
 *
 * Copyright(C) 2001-2003 Salvatore Sanfilippo <antirez@invece.org>
 * All rights reserved.
 *
 * -----------------------------------------------------------------------------
 * Design principles:
 *
 * - This library is little and probably not so flexible nor
 *   full-featured. The goal is to have something of useful
 *   enough to build stuff like mysql queries without to care
 *   about allocation, but with very simple code so that security
 *   auditing is quite simple.
 * - security is more important than speed in this context, so there
 *   is some redundant and useless check to prevent that some unsane use
 *   become a security problem.
 * - while the library is binary-safe the buffers are implicitly
 *   nul termined. Even an empty buffer just initialized points
 *   to an empty nul termined string. This prevents problems passing
 *   strings that the user never nul-termined to functions that
 *   expects nul-termined strings.
 * - memory is more important than speed in this context, so we do often
 *   realloc to change the buffer size even if not required.
 *   This should protect about strange usage patterns that may result
 *   in a lot of memory allocated.
 *
 * -----------------------------------------------------------------------------
 * Security auditing history:
 * format is SECAUDIT(date)(time spent in seconds)(audited part)
 *
 * SECAUDIT(Dec 18 2001)(3600)(all)
 * SECAUDIT(Aug 19 2003)(600)(adbuf_printf)
 *
 * After the last security auditing the code changed, so a new
 * auditing is needed as fast as possible.
 * Remember to audit adbuf.h too.
 *
 * -----------------------------------------------------------------------------
 * CHANGES
 *
 * 18 Aug 2003	- Changes section just created.
 * 19 Aug 2003  - Added adbuf_printf().
 *
 * -----------------------------------------------------------------------------
 * HISTORY OF SECURITY VULNERABILITIES
 *
 * - Nothing discovered for now.
 *
 * -----------------------------------------------------------------------------
 * TODO
 *
 * - adbuf_slice(), with Python-like semantics
 * - adbuf_split(), similar to the TCL split command
 * - minimal documentation
 */

/* $Id: adbuf.c,v 1.1.1.1 2003/08/31 17:24:00 antirez Exp $ */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "adbuf.h"

/* initialize a new buffer. The new empty buffer will
 * appear as an empty nul terminated string to functions
 * that expects a string */
int adbuf_init(struct adbuf *b)
{
	b->buf = malloc(1);
	/* note that if the allocation fails b->buf is set to NULL
	 * so it's safe to call adbuf_free() after a failed initialization */
	if (b->buf == NULL)
		return 1;
	b->buf[0] = '\0';
	b->size = 1;
	b->left = 1;
	return 0;
}

/* free a buffer */
void adbuf_free(struct adbuf *b)
{
	if (b->buf) { /* not really needed with sane libC */
		free(b->buf);
		b->buf = NULL;
	}
}

/* reset the buffer */
int adbuf_reset(struct adbuf *b)
{
	adbuf_free(b);
	return adbuf_init(b);
}

/* add data to the buffer 'b'. return 0 on success, 1 on out of memory.
 * len = 0 and data = NULL is valid */
int adbuf_add(struct adbuf *b, void *data, size_t len)
{
	if (adbuf_ptr(b) == NULL)
		return 1; /* bad buffer in input */
	if (len == 0)
		return 0; /* nothing to add */
	if ((len+1) > b->left) { /* need one more byte to add a nul term */
		size_t newsz = b->size + len + ADBUF_INCR;
		void *t = realloc(b->buf, newsz);

		if (t == NULL)
			return 1; /* out of memory */
		b->buf = t;
		b->left += len + ADBUF_INCR;
		b->size = newsz;
	}
	memcpy(b->buf + adbuf_used(b), data, len);
	b->buf[adbuf_used(b)+len] = '\0'; /* always nul term */
	b->left -= len;
	return 0;
}

/* adbuf_addchar() is like adbuf_add() when {len} = 1, but sligthly
 * optmized to add just one byte */
int adbuf_addchar(struct adbuf *b, int c)
{
	if (adbuf_ptr(b) == NULL)
		return 1; /* bad buffer in input */
	if (b->left >= 2) {
		unsigned char *p = b->buf + adbuf_used(b);

		*p = c;
		*(p+1) = '\0';
		b->left -= 1;
		return 0;
	} else {
		unsigned char t[1];

		t[0] = c;
		return adbuf_add(b, &t, 1);
	}
	return 0; /* unreached */
}

/* add the given nul terminated string */
int adbuf_strcat(struct adbuf *b, char *string)
{
	return adbuf_add(b, string, strlen(string));
}

/* concatenate the buffer b to the buffer a */
int adbuf_cat(struct adbuf *a, struct adbuf *b)
{
	return adbuf_add(a, b->buf, adbuf_used(b));
}

/* cut the buffer to 'count' bytes on the right. If the used buffer is
 * already smaller than 'count' no operation is performed.
 * The function preserves the nul term.
 * On success zero is returned. The function returns 1 on out of memory */
int adbuf_cut(struct adbuf *b, size_t count)
{
	char *t;

	if (adbuf_ptr(b) == NULL)
		return 1; /* bad buffer in input */
	if (count >= adbuf_used(b))
		return 0;
	count++; /* preserve space for the nul term */
	t = realloc(b->buf, count);
	if (t == NULL)
		return 1; /* out of memory */
	t[count-1] = '\0';
	b->buf = t;
	b->size = count;
	b->left = 1; /* the nul term is conceptually free space */
	return 0;
}

/* discard count characters on the left */
int adbuf_ltrim(struct adbuf *b, size_t count)
{
	char *t;
	size_t newlen;

	if (adbuf_ptr(b) == NULL)
		return 1; /* bad buffer in input */
	if (count == 0) /* nothing to trim */
		return 0;
	/* to discard all the buffer on the left is just
	 * the same as to reset the buffer */
	if (count >= adbuf_used(b))
		return adbuf_reset(b);
	newlen = adbuf_used(b)-count;
	t = malloc(newlen+1);	/* add one byte for the nul term */
	if (t == NULL)
		return 1; /* out of memory */
	memcpy(t, adbuf_ptr(b)+count, newlen);
	t[newlen] = '\0';
	free(b->buf);
	b->buf = t;
	b->size = newlen+1;
	b->left = 1;
	return 0;
}

/* discard count caracters on the right */
int adbuf_rtrim(struct adbuf *b, size_t count)
{
	return adbuf_cut(b, adbuf_used(b)-count);
}

#define ADBUF_ITOABUFSZ 32 /* ok for 64bit integers and more */

/* add the string rappresentation of the long integer l */
int adbuf_add_long(struct adbuf *b, long l)
{
	int n = 0;
	char s[ADBUF_ITOABUFSZ];
	char *p = s+ADBUF_ITOABUFSZ-1;

	*p-- = '\0';
	if (l < 0) {
		n = 1;
		l = -l;
	}
	while(p > s) {
		*p-- = '0' + (l % 10);
		l /= 10;
		if (l == 0)
			break;
	}
	if (n)
		*p-- = '-';
	p++;
	return adbuf_strcat(b, p);
}

/* the same as adbuf_add_long() but with unsigned integers */
int adbuf_add_ulong(struct adbuf *b, unsigned long l)
{
	char s[ADBUF_ITOABUFSZ];
	char *p = s+ADBUF_ITOABUFSZ-1;
	*p-- = '\0';
	while(p >= s) {
		*p-- = '0' + (l % 10);
		l /= 10;
		if (l == 0)
			break;
	}
	p++;
	return adbuf_strcat(b, p);
}

/* clone the buffer src in the buffer dst.
 * The buffers will be indipendent */
int adbuf_clone(struct adbuf *src, struct adbuf *dst)
{
	if (adbuf_ptr(src) == NULL)
		return 1; /* bad buffer in input */
	if (adbuf_init(dst))
		return 1; /* out of memory */
	return adbuf_add(dst, adbuf_ptr(src), adbuf_used(src));
}

/* Concat to the buffer using printf-like format.
 * Note that while this function try to detect
 * non-C99 vsnprintf() behaviour, it can be
 * unsafe with some vsnprintf() implementation.
 *
 * On Linux with glibc >= 2.1, and recent *BSDs, and
 * in any other system with a C99-wise vsprintf(), it is sane.
 * On Linux with glibc < 2.1 it should be still secure,
 * but the behaviour is different (unable to handle strings
 * with more than ADBUF_PRINTF_BUFSZ chars).
 * On other non-C99 systems be prepared to random results. */
#define ADBUF_PRINTF_BUFSZ	1024
int adbuf_printf(struct adbuf *dst, const char *fmt, ...)
{
	char buf[ADBUF_PRINTF_BUFSZ];
	int retval;
	va_list ap;

	va_start(ap, fmt);
	retval = vsnprintf(buf, ADBUF_PRINTF_BUFSZ, fmt, ap);
	buf[ADBUF_PRINTF_BUFSZ-1] = '\0';
	va_end(ap);

	if (retval <= -1) { /* pre-C99 vsnprintf() behaviour */
		/* We just append the output without to care
		 * about a too slow buffer. This isn't a security
		 * issue, but the semantics of adbuf_printf() changes
		 * on this systems. */
		return adbuf_add(dst, buf, strlen(buf));
	}
	if (retval >= ADBUF_PRINTF_BUFSZ) { /* PRINTF_BUFSZ wasn't enough */
		/* Use dynamic allocation */
		char *dynbuf;
		int newretval;

		if ((dynbuf = malloc(retval+1)) == NULL)
			return 1; /* Out of memory */
		va_start(ap, fmt);
		newretval = vsnprintf(dynbuf, retval+1, fmt, ap);
		dynbuf[retval] = '\0';
		va_end(ap);

		/* If we can trust the return value, we can avoid
		 * strlen() */
		if (newretval == retval) {
			int rv;
			rv = adbuf_add(dst, dynbuf, retval);
			free(dynbuf);
			return rv;
		} else { /* On strange results we are more prudent */
			int rv;
			rv = adbuf_add(dst, dynbuf, strlen(dynbuf));
			free(dynbuf);
			return rv;
		}
	} else { /* The simple case */
		return adbuf_add(dst, buf, retval);
	}
}

#ifdef TEST_MAIN

#include <stdio.h>

int main(void)
{
	struct adbuf b, bb;
	int add = 0, i;

	adbuf_init(&b);
	for(i = 0; i < 6; i++)
		adbuf_strcat(&b, ".,;-+*#*+-;,.");
	while(adbuf_used(&b) > 0) {
		for (i = 0; i < add; i++) printf(" ");
		printf("%s\n", adbuf_ptr(&b));
		adbuf_rtrim(&b, 1);
		adbuf_ltrim(&b, 1);
		add++;
	}
	adbuf_free(&b);
	adbuf_init(&b);
	for (i = 0; i < 6000; i++) {
		char c;
		for (c = 'A'; c <= 'Z'; c++)
			adbuf_addchar(&b, c);
	}
	adbuf_rtrim(&b, adbuf_used(&b)-500);
	printf("%s\n", adbuf_ptr(&b));
	adbuf_free(&b);
	adbuf_init(&b);
	adbuf_strcat(&b, "adbuf_printf with small output: ");
	adbuf_printf(&b, "%d %04x", 123456789, 123456789);
	printf("%s\n", adbuf_ptr(&b));
	adbuf_reset(&b);
	for (i = 0; i < 1024; i++) {
		adbuf_addchar(&b, 'X');
	}
	adbuf_init(&bb);
	adbuf_printf(&bb, "%s---%s",
			adbuf_ptr(&b), adbuf_ptr(&b));
	adbuf_free(&b);
	printf("bif printf test... ");
	if (strlen(adbuf_ptr(&bb)) == (1024*2)+3)
		printf("PASSED\n");
	else
		printf("FALIED!!!\n");
	adbuf_free(&bb);
	return 0;
}
#endif /* TEST_MAIN */
