/* hex.c -- hex to binary convertion (and vice versa).
 * Copyright (C) 2003 Salvatore Sanfilippo
 * All rights reserved.
 * $Id: hex.c,v 1.2 2003/09/01 00:22:06 antirez Exp $
 */

#include <string.h>

static char hval[256] = {
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 255, 255, 255, 255, 255, 255, 
255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255,  10,  11,  12,  13,  14,  15, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, };

static char hcharset[16] = "0123456789abcdef";

/* Convert hex data in the string pointed by 'hexstr' in binary, and
 * write the result of the conversion to 'dest'.
 * On success 0 is returned, on error non-zero.
 * 'dest' should point to at least len/2 bytes of data,
 * len must be an even number.
 * If len == -1, the function calls strlen() against 'hexstr' to
 * get the length. */
int hextobin(void *dest, char *hexstr, int len)
{
	int i, binlen;
	char *s = hexstr;
	unsigned char *d = dest;

	if (len == -1)
		len = strlen(hexstr);
	if (len % 2)
		return 1; /* error, odd count */
	binlen = len / 2;
	for (i = 0; i < binlen; i++) {
		int high, low;

		high = hval[((unsigned)*s)&0xFF];
		low = hval[((unsigned)*(s+1))&0xFF];
		if (high == 255 || low == 255)
			return 1; /* invalid char in hex string */
		high <<= 4;
		*d = high|low;
		d++;
		s+=2;
	}
	return 0;
}

/* Convert binary data pointed by 'bin' of length 'len' into an hex string
 * rappresentation, writing it at 'dest'. The 'dest' buffer should
 * have enough space to hold (len*2)+1 bytes. The result of the
 * conversion is nul-terminated.
 *
 * This function can't fail. */
void bintohex(char *dest, void *bin, int len)
{
	unsigned char *b = bin;
	int i, high, low;

	for (i = 0; i < len; i++) {
		low = *b & 0xF;
		high = (*b & 0xF0) >> 4;
		*dest++ = hcharset[high];
		*dest++ = hcharset[low];
		b++;
	}
}

/* This example main show the usage. */
#ifdef TESTMAIN
#include <stdio.h>
int main(int argc, char **argv)
{
	unsigned char *buf;
	char *xbuf;
	int hlen, blen, i;

	if (argc == 1)
		exit(1);

	/* Convert from hex to binary */
	hlen = strlen(argv[1]);
	blen = (hlen+1)/2;
	buf = malloc(blen);
	if (!buf)
		exit(1);
	hextobin(buf, argv[1], -1);
	for (i = 0; i < blen; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");

	/* and from binary to hex */
	xbuf = malloc((blen*2)+1);
	if (!xbuf)
		exit(1);
	bintohex(xbuf, buf, blen);
	printf("%s\n", xbuf);
	return 0;
}
#endif
