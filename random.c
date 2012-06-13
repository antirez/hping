/* rc4-based pseudo-random number generator for hping.
 * Copyright (C) 2003 Salvatore Sanfilippo
 * This software is released under the GPL license
 * All rights reserved */

/* $Id: random.c,v 1.3 2004/06/04 07:22:38 antirez Exp $ */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "fixtypes.h"

u_int32_t hp_rand(void);

/* The rc4 sbox */
static unsigned char rc4_sbox[256];
/* This flags is used to initialize the sbox the first time,
 * without an explicit intialization step outside this file. */
static int rc4_seedflag = 0;

/* Initialize the sbox with pseudo random data */
static void hp_rand_init(void)
{
	int i, fd;

	/* Strong sbox initialization */
	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
		read(fd, rc4_sbox, 256);
		close(fd);
	}
	/* Weaker sbox initialization */
	for (i = 0; i < 256; i++) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		if (i&1)
			rc4_sbox[i] ^= (tv.tv_usec >> (i&0xF)) & 0xFF;
		else
			rc4_sbox[i] ^= (tv.tv_sec >> (i&0xF)) & 0xFF;
	}
	rc4_seedflag = 1;
}

#if 0
/* Re-seed the generator with user-provided bytes. Not used for now. */
static void hp_rand_seed(void *seed, size_t len)
{
	int i;

	if (len > 256) len = 256;
	memcpy(rc4_sbox, seed, len);
	/* discard the first 256 bytes of output after the reseed */
	for (i = 0; i < 32; i++)
		(void) hp_rand();
}
#endif

/* Generates a 32bit random number using an RC4-like algorithm */
u_int32_t hp_rand(void)
{
	u_int32_t r = 0;
	unsigned char *rc = (unsigned char*) &r;
	static unsigned int i = 0, j = 0;
	unsigned int si, sj, x;

	/* initialization, only needed the first time */
	if (!rc4_seedflag)
		hp_rand_init();
	/* generates 4 bytes of pseudo-random data using RC4 */
	for (x = 0; x < 4; x++) {
		i = (i+1) & 0xff;
		si = rc4_sbox[i];
		j = (j + si) & 0xff;
		sj = rc4_sbox[j];
		rc4_sbox[i] = sj;
		rc4_sbox[j] = si;
		*rc++ = rc4_sbox[(si+sj)&0xff];
	}
	return r;
}

