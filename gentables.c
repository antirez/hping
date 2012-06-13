#include <stdio.h>
#include <string.h>
#include <math.h>

#include "sbignum.h"

static char *cset = "0123456789abcdefghijklmnopqrstuvwxyz";

static void gen_cset(int hdr);
static void gen_rcset(int hdr);
static void gen_bitstable(int hdr);
static void gen_basetable(int hdr);
static void _gen_basetable(int bytes, double base);
static void gen_basepowtable(int hdr);
static void _gen_basepowtable(int bytes, double base);
static unsigned long lexp(unsigned long b, int e);
static int nbits(unsigned char x);
static double logbn(double base, double n);

#define EFL 16	/* elements for line */

int main(int argc, char **argv)
{
	int hdr = argc-1;
	argv = argv;

	if (hdr) {
		printf(	"#ifndef _SBN_TABLES_H\n"
			"#define _SBN_TABLES_H\n"
			"\n"
			"#include <sys/types.h>\n\n");
	} else {
		printf(	"#include \"tables.h\"\n"
			"#include \"sbignum.h\"\n\n");
	}
	gen_cset(hdr);
	gen_rcset(hdr);
	gen_bitstable(hdr);
	gen_basetable(hdr);
	gen_basepowtable(hdr);
	if (hdr) {
		printf("\n#endif /* _SBN_TABLES_H */\n");
	}
	return 0;
}

void gen_cset(int hdr)
{
	if (hdr) {
		printf("extern char *cset;\n");
		return;
	}
	printf("/* maps a number to a char */\n");
	printf("char *cset = \"%s\";\n\n", cset);
}

void gen_rcset(int hdr)
{
	int i;

	if (hdr) {
		printf("extern int8_t r_cset[256];\n");
		return;
	}
	printf("/* maps a char to a number */\n");
	printf("int8_t r_cset[256] = {\n");
	for (i = 0; i < 256; i++) {
		char *p;
		p = strchr(cset, i);
		if (!(i%EFL))
			printf("\t");
		if (!p || !i) {
			printf("-1, ");
		} else {
			printf("%2d, ", p-cset);
		}
		if (!((i+1) % EFL))
			printf("\n");
	}
	printf("};\n\n");
}

int nbits(unsigned char x)
{
	int i = 8;
	int bits = 0;
	do {
		bits += x & 1;
		x >>= 1;
	} while(--i);
	return bits;
}

void gen_bitstable(int hdr)
{
	int i;

	if (hdr) {
		printf("extern int8_t bitstable[256];\n");
		return;
	}
	printf("/* bitstable[n] is the number of set bits\n"
	       " * in the number 'n' */\n");
	printf("int8_t bitstable[256] = {\n");
	for (i = 0; i < 256; i++) {
		if (!(i%EFL))
			printf("\t");
		printf("%d, ", nbits(i));
		if (!((i+1) % EFL))
			printf("\n");
	}
	printf("};\n\n");
}

double logbn(double base, double n)
{
	return log(n)/log(base);
}

void _gen_basetable(int bytes, double base)
{
	int i;

	printf("#if ATOMBYTES == %d\n", bytes);
	printf("double basetable[%d] = {\n", SBN_MAXBASE+1);
	for (i = 0; i <= SBN_MAXBASE; i++) {
		if (i < 2) {
			printf("\t0, /* unused */\n");
			continue;
		}
		printf("\t%f, /* (log of %d in base %.0f) */\n",
			logbn(i, base), i, base);
	}
	printf("};\n#endif\n\n");
}

#define BT_8BITBASE	256U
#define BT_16BITBASE	65536U
#define BT_32BITBASE	4294967296U

void gen_basetable(int hdr)
{
	if (hdr) {
		printf("extern double basetable[%d];\n", SBN_MAXBASE+1);
		return;
	}
	printf("/* basetable[b] = number of digits needed to convert\n"
	       " * an mpz atom in base 'b' */\n");
	_gen_basetable(1, BT_8BITBASE);
	_gen_basetable(2, BT_16BITBASE);
	_gen_basetable(4, BT_32BITBASE);
}

/* return b^e */
unsigned long lexp(unsigned long b, int e)
{
	unsigned long p = b;
	if (!e) return 1;
	while(--e)
		p *= b;
	return p;
}

void _gen_basepowtable(int bytes, double base)
{
	int i;

	base--;
	printf("#if ATOMBYTES == %d\n", bytes);
	printf("struct sbn_basepow basepowtable[%d] = {\n", SBN_MAXBASE+1);
	for (i = 0; i <= SBN_MAXBASE; i++) {
		unsigned long bexp;
		unsigned long bpow;
		if (i < 2) {
			printf("\t{0,0}, /* unused */\n");
			continue;
		}
		bexp = (unsigned long) floor(logbn(i, base));
		bpow = lexp(i, bexp);
		printf("\t{%luU, %luU}, /* floor(log of %d in base %.0f) */\n",
			bpow, bexp, i, base);
	}
	printf("};\n#endif\n\n");
}

void gen_basepowtable(int hdr)
{
	if (hdr) {
		printf(	"struct sbn_basepow {\n"
			"	unsigned long maxpow;\n"
			"	unsigned long maxexp;\n"
			"};\n");
		printf("extern struct sbn_basepow basepowtable[%d];\n",
			SBN_MAXBASE+1);
		return;
	}
	printf(
	"/* basepowtable[b] = the first column is the biggest power of 'b'\n"
	" * that fits in mpz_atom_t, the second column is the exponent\n"
	" * 'e' so that b^e = the value of the first column */\n");
	_gen_basepowtable(1, BT_8BITBASE);
	_gen_basepowtable(2, BT_16BITBASE);
	_gen_basepowtable(4, BT_32BITBASE);
}
