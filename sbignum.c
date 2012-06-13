/* antirez's arbitrary precision integer math library.
 *
 * $Id: sbignum.c,v 1.3 2003/10/02 08:21:42 antirez Exp $
 *
 * This library was implemented only to joke a bit with the bignum issues,
 * don't expect this is very fast or well tested.
 * Note that in many applications you should check that the arbitrary
 * precision math implementation is very reliable.
 *
 * (news! actually I'm using it for hping3, so starting from
 *  now it is something like a real project.)
 *
 * NOTE: if you need a very good bignums implementation check-out GMP
 *       at http://swox.com/gmp/ it is very fast and reliable.
 *
 * This library API is almost GMP compatible for the subset of
 * functions exported.
 *
 * COPYRIGHT NOTICE
 * ----------------
 *
 * Copyright(C) 2002-2003 Salvatore Sanfilippo <antirez@invece.org>
 * All rights reserved.
 *
 * This code and the documentation is released under the GPL license
 * version 2 of the license. You can get a copy of the license at
 * http://www.gnu.org/licenses/gpl.html
 * A copy of the license is distributed with this code,
 * see the file COPYING. */

/* History of important bugs:
 *
 * 28 Feb 2002: Bad casting in low-level subtraction generated bad results
 *              for particular pairs of numbers. It was a bit hard to
 *		discover the real origin of the bug since all started
 *		with a strange behaviour of the Fermat little theorem.
 *		This was since the modular reduction uses the low-level
 *		subtraction to perform its work. Of course now it's fixed.
 *
 * 12 Sep 2003: Fixed a memory leak in mpz_tostr().
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>

#include "sbignum.h"
#include "sbignum-tables.h"

/* All the function with the _raw suffix don't care about the sign
 * and works if the last operand, that's specified as a mpz_atom_t pointer
 * and a u_int32_t length is stored in statically allocated memory, while
 * higher level functions expect operands declared as mpz_t and initialized
 * with mpz_init(). */

/* Macros and functions starting with the '_' character are usually not
 * exported faster versions of normal functions, that do some unsane assumption
 * like there is enough memory to store the result and so on.
 * They are used to build more complex functions */

/* --------------------------- Low level functions -------------------------- */

/* For the actual list of supported functions see sbignum.h */

/* inititialization/allocation */
static int	mpz_zero_realloc(mpz_ptr z, u_int32_t i);
static void	mpz_zero(mpz_ptr z);
/* shifting */
static int	mpz_lshiftword(mpz_ptr r, u_int32_t i);
static int	mpz_rshiftword(mpz_ptr r, u_int32_t i);
/* comparision */
static int32_t mpz_cmpabsi_raw(mpz_ptr a, mpz_atom_t *d, u_int32_t l);
static int32_t mpz_cmpabs(mpz_ptr a, mpz_ptr b);
/* addition */
static int	mpz_addi_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l);
/* subtraction */
static int	mpz_subi_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l);
/* multiplication */
static int	mpz_muli_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l);
/* division */
static int	mpz_divi_qr_raw(mpz_ptr q, mpz_ptr r, mpz_ptr z, mpz_atom_t *d,
								 u_int32_t l);
static int	mpz_divi_r_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l);
/* number theoretic functions */
static int	mpz_gcd_raw(mpz_ptr g, mpz_ptr a, mpz_atom_t *b, u_int32_t l);
/* to/from mpz conversions */
static int	mpz_tostr(mpz_ptr z, u_int32_t b, void *s, size_t l);
/* random numbers */
static void	sbn_rand_init(void);

/* ================================== MPZ =================================== */

#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))

/* 32bit integer to mpz conversion */
#if ATOMBYTES == 4
#define u32tompz(t,u,l) \
	mpz_atom_t t[1]; \
	u_int32_t l = 0; \
	t[0] = u; \
	if (t[0]) l = 1
#elif ATOMBYTES == 2
#define u32tompz(t,u,l) \
	mpz_atom_t t[2]; \
	u_int32_t l = 0; \
	t[0] = u & MPZ_MASK; u >>= MPZ_SHIFT; \
	t[1] = u & MPZ_MASK; u >>= MPZ_SHIFT; \
	if (t[1]) l = 1; \
	else if (t[0]) l = 2
#elif ATOMBYTES == 1
#define u32tompz(t,u,l) \
	mpz_atom_t t[4]; \
	u_int32_t l = 0; \
	t[0] = u & MPZ_MASK; u >>= MPZ_SHIFT; \
	t[1] = u & MPZ_MASK; u >>= MPZ_SHIFT; \
	t[2] = u & MPZ_MASK; u >>= MPZ_SHIFT; \
	t[3] = u & MPZ_MASK; u >>= MPZ_SHIFT; \
	if (t[3]) l = 4; \
	else if (t[2]) l = 3; \
	else if (t[1]) l = 2; \
	else if (t[0]) l = 1
#endif

/* shift/andmask needed to division and modulo operation for ATOMBITS:
 * a / ATOMBITS == A >> DIVATOMBITS_SHIFT
 * a % ATOMBITS == A & MODATOMBITS_MASK */
#if ATOMBYTES == 4
#define DIVATOMBITS_SHIFT 5
#elif ATOMBYTES == 2
#define DIVATOMBITS_SHIFT 4
#elif ATOMBYTES == 1
#define DIVATOMBITS_SHIFT 3
#endif
#define MODATOMBITS_MASK ((1<<DIVATOMBITS_SHIFT)-1)

#define u32pack(mpz,t,l) \
do { \
	(mpz)->l = l; \
	(mpz)->a = l; \
	(mpz)->s = 0; \
	(mpz)->d = t; \
} while(0)

/* Raw inizialization of mpz_t elements */
#define _mpz_raw_init(z, d, l, a, s) \
do { \
	(z)->d = d; \
	(z)->l = l; \
	(z)->a = a; \
	(z)->s = s; \
}

#define _mpz_neg(z) \
do { \
	(z)->s ^= 1; \
} while(0)

/* ------------------------ debugging macros -------------------------------- */

#define debugprint(m,z) do { \
	char *_s = mpz_get_str(NULL, 10, z); \
	printf("[%d]%s\n", m, _s); \
	free(_s); \
} while(0)

#define debugprint2(m,z) do { \
	char *_s = mpz_get_str(NULL, 2, z); \
	printf("[%d]%s\n", m, _s); \
	free(_s); \
} while(0)

/* ---------------------- initialization/allocation ------------------------- */

/* Initialize a relative bignum.
 * return values: none, can't fail */
void mpz_init(mpz_ptr z)
{
	z->d = NULL;
	z->a = z->l = z->s = 0;
}

/* This function is used every time we need to set the z->d[l] word in the
 * z->d array of the mpz_t type. It performs the allocation when
 * needed. So if you call it with l = 0, there is anyway at least
 * one word allocated. Warning: the normalization inside some function
 * relies on this behaviour.
 *
 * return values:
 *	SBN_OK		on success
 *	SBN_MEM		on out of memory
 *
 * On error the previous memory configuration and memory of 'z'
 * is untouched.
 *
 * The new words are initialized to zero.
 * Note that this function relies on an ANSI-C realloc() that
 * acts like free if the 'size' = 0, and return NULL in such a case,
 * and also acts like malloc if the ptr = NULL. */
int mpz_realloc(mpz_ptr z, u_int32_t i)
{
	void *new;
	u_int32_t j;

	if (i < z->a)
		return SBN_OK;
	new = realloc(z->d, (i+1)*MPZ_ATOMSZ);
	if (new == NULL)
		return SBN_MEM;
	z->d = new;
	/* set the new words to zero */
	for (j = z->a; j <= i; j++)
		z->d[j] = 0;
	z->a = j; /* j = i+1 here */
	return SBN_OK;
}

/* Normalize the length of z, that's to set z->l accordly to the
 * most non-zero significant digit. Assume that all the storage
 * is initialized to zero (that's a global assuption). */
void mpz_normalize(mpz_ptr z)
{
	int32_t j;

	if (!z->a)
		return;
	j = z->a-1;
	while(j >= 0) {
		if (z->d[j])
			break;
		j--;
	}
	z->l = j+1;
	if (z->l == 0)
		z->s = 0;
}

/* If z == 0, make it positive */
void mpz_normalize_sign(mpz_ptr z)
{
	if (z->l == 0)
		z->s = 0;
}

/* inline version of mpz_normalize() that assumes z->a > 0 */
#define _mpz_normalize(z) \
do { \
	int32_t j = (z)->a-1; \
	while(j >=0 && !(z)->d[j]) \
		j--; \
	(z)->l = j+1; \
} while(0)

/* Free a bignum, can't fail */
void mpz_clear(mpz_ptr z)
{
	free(z->d);
}

/* Free a bignum and prepare it to accept up to i+1 digits (base 256)
 * Note: not GMP compatible. Don't alter the sign */
int mpz_zero_realloc(mpz_ptr z, u_int32_t i)
{
	int err;

	if ((err = mpz_realloc(z, i)) != SBN_OK)
		return err;
	mpz_zero(z);
	return SBN_OK;
}

/* raw z = 0
 * Note: not GMP compatible. Don't alter the sign */
void mpz_zero(mpz_ptr z)
{
	if (!z->l)
		return;
	memset(z->d, 0, z->l*MPZ_ATOMSZ);
	z->l = 0;
}

/* Create a stack-allocated clone of the bignum pointed by 'z' and make
 * 'z' pointing to the clone. This is used when the different operators
 * of some operations point to the same object. */
#define _mpz_clone_stack(z) \
do { \
	mpz_ptr t = alloca(sizeof(mpz_t)); \
	t->d = alloca((z)->a*MPZ_ATOMSZ); \
	t->s = (z)->s; \
	t->l = (z)->l; \
	t->a = (z)->a; \
	memcpy(t->d, (z)->d, (z)->a*MPZ_ATOMSZ); \
	(z) = t; \
} while(0)

/* Clone 'z' using the 'L' atoms pointed by 'D' using stack-allocated memory */
#define _mpz_rawclone_stack(z, D, L) \
do { \
	(z)->d = alloca((L)*MPZ_ATOMSZ); \
	(z)->l = z->a = (L); \
	(z)->s = 0; \
	memcpy((z)->d, (D), (L)*MPZ_ATOMSZ); \
} while(0)

/* Create a stack-allocated copy of 'z' in 'r'. 'r' is an mpz_ptr type */
#define _mpz_copy_stack(r, z) \
do { \
	r = alloca(sizeof(mpz_t)); \
	(r)->d = alloca((z)->a*MPZ_ATOMSZ); \
	(r)->s = (z)->s; \
	(r)->l = (z)->l; \
	(r)->a = (z)->a; \
	memcpy((r)->d, (z)->d, (z)->a*MPZ_ATOMSZ); \
} while(0)

/* ----------------------- basic raw operations ----------------------------- */

/* clear the sign flag, so 'z' will be ABS(z) */
#define _mpz_abs(z) \
do { \
	(z)->s = 0; \
} while(0)

/* ---------------------------- bits operations ----------------------------- */
/* compute the number of bits needed to rappresent the number 'z' */
u_int32_t mpz_bits(mpz_ptr z)
{
	u_int32_t bits = (z->l-1) * ATOMBITS;
	mpz_atom_t x = z->d[z->l-1];
	while(x) {
		bits++;
		x >>= 1;
	}
	return bits;
}

/* Set the bit 'i' in 'z' */
int mpz_setbit(mpz_ptr z, u_int32_t i)
{
	u_int32_t atom = i >> DIVATOMBITS_SHIFT;
	u_int32_t bit = i & MODATOMBITS_MASK;
	int err;

	if ((err = mpz_realloc(z, atom)) != SBN_OK)
		return err;
	z->d[atom] |= (mpz_atom_t) 1 << bit;
	if (z->l < atom+1)
		z->l = atom+1;
	return SBN_OK;
}

/* Inline bit pusher that expects the user know what is doing.
 * Used in the division algorithm. */
#define _mpz_setbit(z, i) \
do { \
	u_int32_t _atom = (i)>>DIVATOMBITS_SHIFT; \
	(z)->d[_atom] |= (mpz_atom_t) 1<<((i)&MODATOMBITS_MASK);\
	if ((z)->l < _atom+1) (z)->l = _atom+1; \
} while(0)

/* Faster version without normalization */
#define __mpz_setbit(z, i) \
do { \
	u_int32_t _atom = (i)>>DIVATOMBITS_SHIFT; \
	(z)->d[_atom] |= (mpz_atom_t) 1<<((i)&MODATOMBITS_MASK);\
} while(0)

/* Clear the bit 'i' in 'z' */
int mpz_clrbit(mpz_ptr z, u_int32_t i)
{
	u_int32_t atom = i >> DIVATOMBITS_SHIFT;
	u_int32_t bit = i & MODATOMBITS_MASK;

	if (atom >= z->l)
		return SBN_OK; /* nothing to clear */
	z->d[atom] &= ~((mpz_atom_t) 1 << bit);
	if (atom == z->l-1)
		mpz_normalize(z);
	return SBN_OK;
}

/* Fast clear-bit with normalization */
#define _mpz_clrbit(z, i) \
do { \
	u_int32_t _atom = (i)>>DIVATOMBITS_SHIFT; \
	(z)->d[_atom] &= ~((mpz_atom_t) 1<<((i)&MODATOMBITS_MASK)); \
	if (_atom == z->l-1) \
		_mpz_normalize(z); \
} while(0)

/* Fast clear-bit without normalization */
#define __mpz_clrbit(z, i) \
do { \
	u_int32_t _atom = (i)>>DIVATOMBITS_SHIFT; \
	(z)->d[_atom] &= ~((mpz_atom_t) 1<<((i)&MODATOMBITS_MASK));\
} while(0)

/* test the bit 'i' of 'z' and return:
 *   0 if the bit 'i' is not set or out of range
 * > 0 if the bit 'i' is set */
int mpz_testbit(mpz_ptr z, u_int32_t i)
{
	u_int32_t atom = i >> DIVATOMBITS_SHIFT;
	u_int32_t bit = i & MODATOMBITS_MASK;

	if (atom >= z->l)
		return 0;
	return (z->d[atom] & ((mpz_atom_t) 1 << bit));
}

/* inline bit tester that expects the user know what is doing.
 * It's used in the division algorithm. Return 0 if the bit is set,
 * non zero if the bit isn't zet */
#define _mpz_testbit(z, i) \
  ((z)->d[(i)>>DIVATOMBITS_SHIFT] & ((mpz_atom_t)1<<((i)&MODATOMBITS_MASK)))

/* Return 1 if 'z' is odd, 0 if it's even. */
#define mpz_is_odd(z) (((z)->l) ? ((z)->d[0] & 1) : 0)

/* The same of mpz_odd() but assume there is at least an word allocated */
#define _mpz_is_odd(z) ((z)->d[0] & 1)
#define _mpz_is_even(z) (!_mpz_is_odd(z))

/* -------------------------------- shifting -------------------------------- */
/* Left shift of 'i' words */
int mpz_lshiftword(mpz_ptr r, u_int32_t i)
{
	int err;

	if (!i)
		return SBN_OK;
	if ((err = mpz_realloc(r, (r->l+i)-1)) != SBN_OK)
		return err;
	memmove(r->d+i, r->d, r->l*MPZ_ATOMSZ);
	memset(r->d, 0, i*MPZ_ATOMSZ);
	r->l += i;
	return SBN_OK;
}

/* Right shift of 'i' words */
int mpz_rshiftword(mpz_ptr r, u_int32_t i)
{
	if (!i)
		return SBN_OK;
	if (i >= r->l) {
		mpz_zero(r);
		return SBN_OK;
	}
	memmove(r->d, r->d+i, (r->l-i)*MPZ_ATOMSZ);
	r->l -= i;
	memset(r->d+r->l, 0, i);
	return SBN_OK;
}

/* Left shift of 'i' bits */
int mpz_lshift(mpz_ptr r, mpz_ptr z, u_int32_t i)
{
	u_int32_t rawshift = i >> DIVATOMBITS_SHIFT;
	u_int32_t bitshift = i & MODATOMBITS_MASK;
	int32_t j;
	mpz_carry_t x;
	int err;

	/* clone 'z' in 'r' */
	if (r != z && ((err = mpz_set(r, z)) != SBN_OK))
		return err;
	if (rawshift && ((err = mpz_lshiftword(r, rawshift)) != SBN_OK))
		return err;
	if (!bitshift)
		return SBN_OK;
	/* We need an additional word */
	if ((err = mpz_realloc(r, r->l+1)) != SBN_OK)
		return err;
	/* note that here we are sure that 'bitshift' <= ATOMBITS */
	if (r->l) {
		for (j = r->l-1; j >= 0; j--) {
			x = (mpz_carry_t) r->d[j] << bitshift;
			r->d[j] = x & MPZ_MASK;
			r->d[j+1] |= x >> ATOMBITS;
		}
		if (r->d[r->l])
			r->l++;
	}
	return SBN_OK;
}

/* Fast 'z' 1 bit left shift. Assume there is allocated space for
 * an additional atom. Handle normalization */
#define _mpz_self_lshift1(z) \
do { \
	int32_t j; \
	for (j = (z)->l-1; j >= 0; j--) { \
		(z)->d[j+1] |= ((z)->d[j] & (1<<(ATOMBITS-1))) >> (ATOMBITS-1);\
		(z)->d[j] <<= 1; \
	} \
	if ((z)->d[(z)->l]) \
		(z)->l++; \
} while(0);

/* Fast 'z' 1 bit left shift + set bit 0 to 'b'. Assume there is allocated
 * space for an additional atom. Handle normalization */
#define _mpz_self_lshift1_setbit0(z, b) \
do { \
	int32_t j; \
	for (j = (z)->l-1; j >= 0; j--) { \
		(z)->d[j+1] |= ((z)->d[j] & (1<<(ATOMBITS-1))) >> (ATOMBITS-1);\
		(z)->d[j] <<= 1; \
	} \
	(z)->d[0] |= b; \
	if ((z)->d[(z)->l]) \
		(z)->l++; \
} while(0);

/* Right shift of 'i' bits */
int mpz_rshift(mpz_ptr r, mpz_ptr z, u_int32_t i)
{
	u_int32_t rawshift = i >> DIVATOMBITS_SHIFT;
	u_int32_t bitshift = i & MODATOMBITS_MASK;
	u_int32_t j;
	mpz_carry_t x;
	int err;

	/* clone 'z' in 'r' */
	if (r != z && ((err = mpz_set(r, z)) != SBN_OK))
		return err;
	if (rawshift && ((err = mpz_rshiftword(r, rawshift)) != SBN_OK))
		return err;
	if (!bitshift)
		return SBN_OK;
	/* note that here we are sure that 'bitshift' <= ATOMBITS */
	if (r->l) {
		r->d[0] >>= bitshift;
		for (j = 1; j < r->l; j++) {
			x = (mpz_carry_t) r->d[j] << (ATOMBITS-bitshift);
			r->d[j] = x >> ATOMBITS;
			r->d[j-1] |= x & MPZ_MASK;
		}
		if (!r->d[r->l-1])
			r->l--;
	}
	return SBN_OK;
}

/* Fast 'z' 1 bit right shift. Handle normalization. Assume z->a != 0
 * (so z->d != NULL), that's: don't call it without a reallocation. */
#define _mpz_self_rshift1(z) \
do { \
	u_int32_t j; \
	(z)->d[0] >>= 1; \
	for (j = 1; j < (z)->l; j++) { \
		(z)->d[j-1] |= ((z)->d[j] & 1) << (ATOMBITS-1); \
		(z)->d[j] >>= 1; \
	} \
	if (!(z)->d[(z)->l-1]) \
		(z)->l--; \
} while(0);

/* -------------------------- bitwise AND OR XOR NOT ------------------------ */
/* 'r' = 'z' bit-AND 'm' */
int mpz_and(mpz_ptr r, mpz_ptr z, mpz_ptr m)
{
	int err;
	u_int32_t j;
	u_int32_t len;

	if (z == m) { /* A AND A = A */
		mpz_set(r, z);
		return SBN_OK;
	}
	len = MIN(z->l, m->l);
	if ((err = mpz_realloc(r, len)) != SBN_OK)
		return err;
	for (j = 0; j < len; j++)
		r->d[j] = z->d[j] & m->d[j];
	memset(r->d+j, 0, r->a - j); /* clear not-used words before normalize */
	mpz_normalize(r);
	return SBN_OK;
}

/* -------------------------------- compare --------------------------------- */

/* The same as mpz_cmpabs() for immediate.
 * Relies on the fact that mpz_cmpabs() don't perform any allocation-related
 * operation on the second operand. */
int32_t mpz_cmpabsi_raw(mpz_ptr a, mpz_atom_t *d, u_int32_t l)
{
	mpz_t b;

	b->d = d;
	b->l = b->a = l;
	b->s = 0;
	return mpz_cmpabs(a, b);
}

/* compare ABS('a') and ABS('b'), return values:
 *	>0	if a > b
 *	 0	if a == b
 *	<0	if a < b
 *
 * 'a->d' and 'b->d' can point to statically allocated memory.
 *
 * Note that we can't use subtraction to return >0 or <0 if a-b != 0
 * since the type for length and atom is unsigned so it may overflow.
 */
int32_t mpz_cmpabs(mpz_ptr a, mpz_ptr b)
{
	int32_t i;

	if (a->l > b->l) return 1;
	if (a->l < b->l) return -1;
	i = a->l;
	while(i--) {
		if (a->d[i] > b->d[i]) return 1;
		if (a->d[i] < b->d[i]) return -1;
	}
	return 0;
}

/* the same as mpz_cmpabs() but 'b' is a 32bit unsigned immediate */
int32_t mpz_cmpabs_ui(mpz_ptr a, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_cmpabs(a, mpz);
}

/* compare 'a' and 'b'. Return values are the same as mpz_cmpabs() */
int32_t mpz_cmp(mpz_ptr a, mpz_ptr b)
{
	if (!a->l && !b->l)	/* 0 == 0 */
		return 0;
	if (a->s == b->s) {	/* same sign */
		if (a->s) return mpz_cmpabs(b,a); /* both negative */
		return mpz_cmpabs(a,b); /* both positive */
	}
	/* one negative, one positive */
	if (a->s)
		return -1;
	return 1;
}

/* The same as mpz_cmp() with unsigned 32bit immediate */
int32_t mpz_cmp_ui(mpz_ptr a, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_cmp(a, mpz);
}

/* signed integer version */
int32_t mpz_cmp_si(mpz_ptr a, int32_t s)
{
	mpz_t mpz;
	u_int32_t u = (s > 0) ? s : -s;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	mpz->s = s < 0;
	return mpz_cmp(a, mpz);
}

/* ---------------------------- addition ------------------------------------ */

/* Raw add of immediate, don't care about the sign since
 * it's up to the caller */
int mpz_addi_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l)
{
	int err;
	u_int32_t maxi = MAX(z->l, l);
	mpz_atom_t car = 0;
	mpz_carry_t sum;
	u_int32_t j;
	mpz_atom_t *t = NULL;

	if (r->d == d) {
		if ((t = malloc(l*MPZ_ATOMSZ)) == NULL)
			return SBN_MEM;
		memcpy(t, d, l*MPZ_ATOMSZ);
		d = t;
	}
	/* two sum of a,b requires at max MAX(len(a),len(b))+1 bytes */
	if (r != z && ((err = mpz_zero_realloc(r, maxi)) != SBN_OK))
		return err;
	if ((err = mpz_realloc(z, (r == z) ? maxi : l)) != SBN_OK)
		return err;
	for(j = 0; j < l; j++) {
		sum = (mpz_carry_t) d[j] + z->d[j] + car;
		car = sum >> MPZ_SHIFT;
		sum &= MPZ_MASK;
		r->d[j] = sum;
	}
	for (j = l; j < z->l; j++) {
		sum = (mpz_carry_t) z->d[j] + car;
		car = sum >> MPZ_SHIFT;
		sum &= MPZ_MASK;
		r->d[j] = sum;
	}
	if (car) {
		r->d[j] = car;
		j++;
	}
	r->l = j; /* mpz_normalize() not needed */
	if (t)
		free(t);
	return SBN_OK;
}

/* Add 'z' and a 32bit unsigned integer 'u' and put the result in 'r'
 * Relies on the ability of mpz_add() to accept the last operator
 * statically allocated */
int mpz_add_ui(mpz_ptr r, mpz_ptr z, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_add(r, z, mpz);
}

/* The same as mpz_add_ui but with signed integer */
int mpz_add_si(mpz_ptr r, mpz_ptr z, int32_t s)
{
	mpz_t mpz;
	u_int32_t u = (s > 0) ? s : -s;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	mpz->s = s < 0;
	return mpz_add(r, z, mpz);
}

/* 'r' = 'a' + 'b'
 * b->d can point to statically allocated data */
int mpz_add(mpz_ptr r, mpz_ptr a, mpz_ptr b)
{
	int cmp = mpz_cmpabs(a, b);
	int err;

	/* both positive or negative */
	if (a->s == b->s) {
		err = mpz_addi_raw(r, a, b->d, b->l);
		r->s = a->s;
		return err;
	}
	/* different signs if we are here */
	if (a->s) { /* a negative, b positive */
		if (cmp >= 0) { /* a >= b */
			err = mpz_subi_raw(r, a, b->d, b->l);
			r->s = (r->l == 0) ? 0 : 1; /* negative */
			return err;
		} else { /* a < b */
			err = mpz_subi_raw(r, b, a->d, a->l);
			r->s = 0; /* positive */
			return err;
		}
	} else { /* a positive, b negative */
		if (cmp >= 0) { /* a >= b */
			err = mpz_subi_raw(r, a, b->d, b->l);
			r->s = 0; /* positive */
			return err;
		} else { /* a < b */
			err = mpz_subi_raw(r, b, a->d, a->l);
			r->s = (r->l == 0) ? 0 : 1; /* negative */
			return err;
		}
	}
	return SBN_OK; /* not reached */
}

/* ---------------------------- subtraction --------------------------------- */

/* WARNING: assume z > d */
int mpz_subi_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l)
{
	int err;
	mpz_scarry_t sub;
	mpz_atom_t car = 0;
	u_int32_t j;
	mpz_atom_t *t = NULL;

	if (r->d == d) {
		if ((t = malloc(l*MPZ_ATOMSZ)) == NULL)
			return SBN_MEM;
		memcpy(t, d, l*MPZ_ATOMSZ);
		d = t;
	}
	if (r != z && ((err = mpz_set(r, z)) != SBN_OK))
		return err;
	for (j = 0; j < l; j++) {
		sub = (mpz_scarry_t) z->d[j] - car - d[j];
		car = 0;
		if (sub < 0) {
			sub += MPZ_BASE;
			car = 1;
		}
		r->d[j] = sub;
	}
	for (j = l; j < z->l; j++) {
		sub = (mpz_scarry_t) z->d[j] - car;
		car = 0;
		if (sub < 0) {
			sub += MPZ_BASE;
			car = 1;
		}
		r->d[j] = sub;
	}
	r->l = j;
	mpz_normalize(r);
	if (t)
		free(t);
	return SBN_OK;
}

/* 'r' = 'a' - 'b'
 * b->d can be statically allocated data */
int mpz_sub(mpz_ptr r, mpz_ptr a, mpz_ptr b)
{
	int cmp = mpz_cmpabs(a, b);
	int err;

	/* different signs? */
	if (a->s != b->s) {
		err = mpz_addi_raw(r, a, b->d, b->l);
		r->s = a->s;
		return err;
	}
	/* both positive or negative if we are here */
	if (a->s) { /* both negative */
		if (cmp >= 0) { /* a >= b */
			err = mpz_subi_raw(r, a, b->d, b->l);
			r->s = (r->l == 0) ? 0 : 1; /* negative */
			return err;
		} else { /* a < b */
			err = mpz_subi_raw(r, b, a->d, a->l);
			r->s = 0; /* positive */
			return err;
		}
	} else { /* both positive */
		if (cmp >= 0) { /* a >= b */
			err = mpz_subi_raw(r, a, b->d, b->l);
			r->s = 0; /* positive */
			return err;
		} else { /* a < b */
			err = mpz_subi_raw(r, b, a->d, a->l);
			r->s = (r->l == 0) ? 0 : 1; /* negative */
			return err;
		}
	}
	return SBN_OK; /* not reached */
}

/* mpz_sub() with immediate.
 * Relies on the fact that mpz_sub() works if the last argument
 * is statically allocated */
int mpz_sub_ui(mpz_ptr r, mpz_ptr z, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_sub(r, z, mpz);
}

/* like mpz_sub_ui but with signed integer */
int mpz_sub_si(mpz_ptr r, mpz_ptr z, int32_t s)
{
	mpz_t mpz;
	u_int32_t u = (s > 0) ? s : -s;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	mpz->s = s < 0;
	return mpz_sub(r, z, mpz);
}

/* ------------------------------- product ---------------------------------- */

/* Raw multiplication of immediate, don't care about the sign
 * since it's up to the caller */
int mpz_muli_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l)
{
	int err;
	u_int32_t maxi = z->l+l;
	mpz_atom_t car;
	mpz_carry_t mul;
	u_int32_t j, i;
	mpz_t t, rt;
	mpz_ptr rbak = NULL;
	int tmptarget = (r == z);
	mpz_atom_t *x = NULL;

	/* Make a copy of 'd' if it's == r */
	if (r->d == d) {
		if ((x = malloc(l*MPZ_ATOMSZ)) == NULL)
			return SBN_MEM;
		memcpy(x, d, l*MPZ_ATOMSZ);
		d = x;
	}
	/* if r and z are the same we need a temp bignum target */
	if (tmptarget) {
		rbak = r;
		r = rt;
		mpz_init(r);
		r->s = rbak->s; /* preserve the original sign */
	}
	/* two product of a,b requires at max len(a)+len(b) bytes */
	if ((err = mpz_zero_realloc(r, maxi)) != SBN_OK)
		goto error;
	/* initialize the temp var */
	mpz_init(t);
	if ((err = mpz_realloc(t, maxi)) != SBN_OK)
		goto error;
	for(j = 0; j < l; j++) {
		car = 0;
		mpz_zero(t);
		for (i = 0; i < z->l; i++) {
			/* note that A = B * C + D + E
			 * with A of N*2 bits and C,D,E of N bits
			 * can't overflow since:
			 * (2^N-1)*(2^N-1)+(2^N-1)+(2^N-1) == 2^(2*N)-1 */
			mul = (mpz_carry_t) d[j] * z->d[i] + car + r->d[i+j];
			car = mul >> MPZ_SHIFT;
			mul &= MPZ_MASK;
			r->d[i+j] = mul;
		}
		if (car)
			r->d[i+j] = car;
	}
	r->l = maxi;
	mpz_normalize(r);
	if (tmptarget && ((err = mpz_set(rbak, rt)) != SBN_OK))
		goto error;
	err = SBN_OK;
	/* fall through */
error:
	mpz_clear(t);
	if (tmptarget)
		mpz_clear(rt);
	if (x)
		free(x);
	return err;
}

/* 'r' = 'z' * 'f' */
int mpz_mul(mpz_ptr r, mpz_ptr z, mpz_ptr f)
{
	r->s = z->s^f->s; /* the sign is the xor of the two sings */
	return mpz_muli_raw(r, z, f->d, f->l);
}

/* Mul 'z' and a 32bit unsigned integer 'u' and put the result in 'r'
 * We don't need to touch the sign since the factor is >= 0 */
int mpz_mul_ui(mpz_ptr r, mpz_ptr z, u_int32_t u)
{
	u32tompz(t,u,l);
	r->s = z->s;
	return mpz_muli_raw(r, z, t, l);
}

/* Like mpz_mul_ui but with signed integer */
int mpz_mul_si(mpz_ptr r, mpz_ptr z, int32_t s)
{
	u_int32_t u = (s > 0) ? s : -s;
	u32tompz(t,u,l);
	r->s = z->s^(s<0);
	return mpz_muli_raw(r, z, t, l);
}

/* 'r' = i! */
int mpz_fac_ui(mpz_ptr r, u_int32_t i)
{
	u_int32_t j;
	int err;

	if (!i) {
		mpz_setzero(r);
		return SBN_OK;
	}
	if ((err = mpz_set_ui(r, 1)) != SBN_OK)
		return err;
	for (j = 2; j <= i; j++)
		if ((err = mpz_mul_ui(r, r, j)) != SBN_OK)
			return err;
	return SBN_OK;
}

/* --------------------------- exponentialization --------------------------- */

/* compute b^e mod m.
 * Note that there are much faster ways to do it.
 * see www.nc.com for more information */
int mpz_powm(mpz_ptr r, mpz_ptr b, mpz_ptr e, mpz_ptr m)
{
	int rs = 0, err;
	mpz_t B, E;

	if (e->s) /* can't handle negative exponents */
		return SBN_INVAL;

	/* handle overlapping of modulo and result */
	if (r == m)
		_mpz_clone_stack(m);
	/* we need to work on copies of base and exponent */
	mpz_init(B);
	mpz_init(E);
	if ((err = mpz_set(B, b)) != SBN_OK)
		return err;
	if ((err = mpz_set(E, e)) != SBN_OK) {
		mpz_clear(B);
		return err;
	}
	/* make the base positive, but first compute the power sign,
	 * that's negative only if the base is negative and exponent odd */
	if (B->s && _mpz_is_odd(E))
		rs = 1;
	_mpz_abs(B);
	/* compute r = b^e mod m */
	mpz_set_ui(r, 1);
	while(mpz_cmpabs_ui(E, 1) > 0) {
		if (_mpz_is_odd(E)) {
			if ((err = mpz_mul(r, r, B)) != SBN_OK) goto error;
			if ((err = mpz_mod(r, r, m)) != SBN_OK) goto error;
		}
		_mpz_self_rshift1(E); /* e = e / 2 */
		if ((err = mpz_mul(B, B, B)) != SBN_OK) goto error;
		if ((err = mpz_mod(B, B, m)) != SBN_OK) goto error;
	}
	if ((err = mpz_mul(r, r, B)) != SBN_OK) goto error;
	r->s = rs; /* set the pre-computed sign */
	if ((err = mpz_mod(r, r, m)) != SBN_OK) goto error;
	err = SBN_OK;
	/* fall through */
error:
	mpz_clear(B);
	mpz_clear(E);
	return err;
}

/* Just b^e. The algorithm is just the one of mpz_powm() without
 * the modulo step. */
int mpz_pow(mpz_ptr r, mpz_ptr b, mpz_ptr e)
{
	int rs = 0, err;
	mpz_t B, E;

	if (e->s) /* can't handle negative exponents */
		return SBN_INVAL;

	/* we need to work on copies of base and exponent */
	mpz_init(B);
	mpz_init(E);
	if ((err = mpz_set(B, b)) != SBN_OK)
		return err;
	if ((err = mpz_set(E, e)) != SBN_OK) {
		mpz_clear(B);
		return err;
	}
	/* make the base positive, but first compute the power sign,
	 * that's negative only if the base is negative and exponent odd */
	if (B->s && _mpz_is_odd(E))
		rs = 1;
	_mpz_abs(B);
	/* compute r = b^e */
	mpz_set_ui(r, 1);
	while(mpz_cmpabs_ui(E, 1) > 0) {
		if (_mpz_is_odd(E)) {
			if ((err = mpz_mul(r, r, B)) != SBN_OK) goto error;
		}
		_mpz_self_rshift1(E); /* e = e / 2 */
		if ((err = mpz_mul(B, B, B)) != SBN_OK) goto error;
	}
	if ((err = mpz_mul(r, r, B)) != SBN_OK) goto error;
	r->s = rs; /* set the pre-computed sign */
	err = SBN_OK;
	/* fall through */
error:
	mpz_clear(B);
	mpz_clear(E);
	return err;
}

/* -------------------------- root extraction ------------------------------- */

/* r = floor(sqrt(z)). That's r*r <= z AND (r+1)*(r+1) > z.
 * The algorithm used is very simple but very slow. It exploits
 * the binary rappresentation. This should be replaced since
 * performances are very poor */
int mpz_sqrt(mpz_ptr r, mpz_ptr z)
{
	int j = mpz_bits(z);	/* MSB bit of 'z' */
	int i = ((j-1)/2);	/* MSB bit (sometimes one more) of 'r' */
	int b = i*2;		/* bit to set to obtain 2^i * 2^i */
	int err;
	u_int32_t atoms = j >> DIVATOMBITS_SHIFT;
	mpz_t s, R, X;

	mpz_init(s);
	mpz_init(R);
	mpz_init(X);
	if (r == z) {
		_mpz_clone_stack(z);
	}
	if ((err = mpz_realloc(s, atoms)) != SBN_OK) return err;
	if ((err = mpz_realloc(R, atoms)) != SBN_OK) return err;
	if ((err = mpz_realloc(X, atoms)) != SBN_OK) return err;
	if ((err = mpz_zero_realloc(r, atoms)) != SBN_OK) return err;
	for(; i >= 0; i--, b -= 2) {
		_mpz_setbit(R, b);
		mpz_addi_raw(X, s, R->d, R->l);
		_mpz_clrbit(R, b);
		if (mpz_cmpabs(X, z) <= 0) {
			mpz_set(s, X);
			_mpz_setbit(r, i);
			_mpz_setbit(R, b+1);
		}
		_mpz_self_rshift1(R);
	}
	mpz_clear(s);
	mpz_clear(R);
	mpz_clear(X);
	return SBN_OK;
}

/* ----------------------------- division ----------------------------------- */

/* Raw division of immediate don't care about the sign
 * since it's up to the caller.
 *
 * compute:
 * 'q' = 'z' / 'd'
 * 'r' = 'z' % 'd'
 *
 * Assume: z >= 0, d > 0, all the arguments must not overlap.
 * Arguments overlapping, sign, etc, are handled in mpz_tdiv_qr().
 * 'z' can be statically allocated.
 *
 * ===========================================================================
 *
 * I got this algorithm from PGP 2.6.3i (see the mp_udiv function).
 * Here is how it works:
 *
 * Input:  N=(Nn,...,N2,N1,N0)radix2
 *         D=(Dn,...,D2,D1,D0)radix2
 * Output: Q=(Qn,...,Q2,Q1,Q0)radix2 = N/D
 *         R=(Rn,...,R2,R1,R0)radix2 = N%D
 *
 * Assume: N >= 0, D > 0
 *
 * For j from 0 to n
 *	Qj <- 0
 *	Rj <- 0
 * For j from n down to 0
 *      R <- R*2
 *	if Nj = 1 then R0 <- 1
 *      if R => D then R <- (R - D), Qn <- 1
 *
 * Note that the doubling of R is usually done leftshifting one position.
 * The only operations needed are bit testing, bit setting and subtraction.
 *
 * Unfortunately it is quite slow. The algoritm is not very fast
 * and the implementation may be smarter. The good point is that
 * it's very simple to implement.
 */
int mpz_divi_qr_raw(mpz_ptr q, mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l)
{
	int bit = mpz_bits(z) - 1;

	mpz_zero_realloc(q, z->l-l+1);
	mpz_zero_realloc(r, l);

	while(bit >= 0) {
		_mpz_self_lshift1_setbit0(r, (_mpz_testbit(z, bit) != 0));
		if (mpz_cmpabsi_raw(r, d, l) >= 0) {
			_mpz_normalize(r);
			mpz_subi_raw(r, r, d, l);
			__mpz_setbit(q, bit);
		}
		bit--;
	}
	_mpz_normalize(q);
	_mpz_normalize(r);
	return SBN_OK;
}

/* The same as mpz_divi_qr_raw() but only the remainder is computed */
int mpz_divi_r_raw(mpz_ptr r, mpz_ptr z, mpz_atom_t *d, u_int32_t l)
{
	int bit = mpz_bits(z) - 1;

	mpz_zero_realloc(r, l);

	while(bit >= 0) {
		_mpz_self_lshift1_setbit0(r, (_mpz_testbit(z, bit) != 0));
		if (mpz_cmpabsi_raw(r, d, l) >= 0) {
			_mpz_normalize(r);
			mpz_subi_raw(r, r, d, l);
		}
		bit--;
	}
	_mpz_normalize(r);
	return SBN_OK;
}

/* Wrapper for the real division function
 * 'q' = 'z' / 'd'
 * 'r' = 'z' % 'd'
 *
 * Assume that q and r are different pointers.
 * d can be statically allocated.
 * Relies on the fact that:
 *	mpz_set() can accept as second argument a statically allocated operator
 *	mpz_cmpabs() can accept as second argument a statically allocated op.
 *	mpz_divi_qr() can accept a statically allocated divident.
 */
int mpz_tdiv_qr(mpz_ptr q, mpz_ptr r, mpz_ptr z, mpz_ptr d)
{
	int cmp;
	int err;

	if (d->l == 0) /* division by zero */
		return SBN_INVAL;
	if (z == d) {
		err = mpz_set_ui(q, 1); /* a/a = 1 */
		if (err != SBN_OK)
			return err;
		mpz_setzero(r); /* a%a = 0 */
		return SBN_OK;
	}
	cmp = mpz_cmpabs(z, d);
	if (cmp < 0) { /* z < d */
		err = mpz_set(r, z); /* a%b = a with a<b */
		if (err != SBN_OK)
			return err;
		mpz_setzero(q); /* a/b = 0 with a<b */
		return SBN_OK;
	} else if (cmp == 0) { /* z = d */
		err = mpz_set_ui(q, 1); /* a/a = 1 */
		if (err != SBN_OK)
			return err;
		mpz_setzero(r); /* a%a = 0 */
		return SBN_OK;
	}
	/* handle the case where z is the same element as q or r */
	if (z == q || z == r)
		_mpz_clone_stack(z);
	/* handle the case where d is the same element as q or r */
	if (d == q || d == r)
		_mpz_clone_stack(d);
	/* the normal case */
	q->s = z->s^d->s; /* the sign is the xor of the two sings */
	r->s = z->s; /* the sign of the remainder is the sign of the divident */
	return mpz_divi_qr_raw(q, r, z, d->d, d->l);
}

/* The same as mpz_tdiv_qr() but the divisor is a 32bit unsigned immediate */
int mpz_tdiv_qr_ui(mpz_ptr q, mpz_ptr r, mpz_ptr z, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_tdiv_qr(q, r, z, mpz);
}

/* Like mpz_tdiv_qr_si but with signed integer */
int mpz_tdiv_qr_si(mpz_ptr q, mpz_ptr r, mpz_ptr z, int32_t s)
{
	mpz_t mpz;
	u_int32_t u = (s > 0) ? s : -s;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	mpz->s = s < 0;
	return mpz_tdiv_qr(q, r, z, mpz);
}

/* Like mpz_tdiv_qr but only the remainder is computed */
int mpz_tdiv_r(mpz_ptr r, mpz_ptr z, mpz_ptr d)
{
	int cmp;

	if (d->l == 0) /* division by zero */
		return SBN_INVAL;
	if (z == d) {
		mpz_setzero(r); /* a%a = 0 */
		return SBN_OK;
	}
	cmp = mpz_cmpabs(z, d);
	if (cmp < 0) { /* z < d */
		if (r == z)
			return SBN_OK;
		return mpz_set(r, z); /* a%b = a with a<b */
	} else if (cmp == 0) { /* z = d */
		mpz_setzero(r); /* a%a = 0 */
		return SBN_OK;
	}
	/* handle the case where z is the same element as r */
	if (z == r)
		_mpz_clone_stack(z);
	/* handle the case where d is the same element as r */
	if (d == r)
		_mpz_clone_stack(d);
	/* the normal case */
	r->s = z->s; /* the sign of the remainder is the sign of the divident */
	return mpz_divi_r_raw(r, z, d->d, d->l);
}

/* The same as mpz_tdiv_r() but the divisor is a 32bit unsigned immediate */
int mpz_tdiv_r_ui(mpz_ptr r, mpz_ptr z, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_tdiv_r(r, z, mpz);
}

/* Like the above but with signed integer */
int mpz_tdiv_r_si(mpz_ptr r, mpz_ptr z, int32_t s)
{
	mpz_t mpz;
	u_int32_t u = (s > 0) ? s : -s;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	mpz->s = s < 0;
	return mpz_tdiv_r(r, z, mpz);
}

/* Like mpz_tdiv_qr but only the quotient is computed.
 * This is just a wrapper for mpz_tdiv_qr() */
int mpz_tdiv_q(mpz_ptr q, mpz_ptr z, mpz_ptr d)
{
	int err;
	mpz_t r;

	mpz_init(r);
	err = mpz_tdiv_qr(q, r, z, d);
	mpz_clear(r);
	return err;
}

/* The same as mpz_tdiv_q() but the divisor is a 32bit unsigned immediate */
int mpz_tdiv_q_ui(mpz_ptr q, mpz_ptr z, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_tdiv_r(q, z, mpz);
}

/* Like the above but with signed integer */
int mpz_tdiv_q_si(mpz_ptr q, mpz_ptr z, int32_t s)
{
	mpz_t mpz;
	u_int32_t u = (s > 0) ? s : -s;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	mpz->s = s < 0;
	return mpz_tdiv_r(q, z, mpz);
}

/* Division by one-atom divident.
 * compute z = z / d;
 * The remainder is returned.
 *
 * Assume: z > 0, d > 0
 * Operands overlapping is not allowed */
mpz_atom_t _mpz_selfdiv1_qr_raw(mpz_ptr z, mpz_atom_t d)
{
	int32_t j;
	mpz_carry_t t;

	/* divide */
	for (t = 0, j = z->l-1; j >= 0; j--) {
		t = (t << MPZ_SHIFT) + z->d[j];
		z->d[j] = t / d;
		t %= d;
	}
	/* normalize */
	if (!z->d[z->l-1])
		z->l--;
	return t;
}

/* Compute z mod m (modular reduction) */
int mpz_mod(mpz_ptr r, mpz_ptr z, mpz_ptr m)
{
	int err;

	if (r == m)
		_mpz_clone_stack(m);
	if ((err = mpz_tdiv_r(r, z, m)) != SBN_OK)
		return err;
	if (r->l && z->s) {
		if (m->s) {
			if ((err = mpz_sub(r, r, m)) != SBN_OK)
				return err;
		} else {
			if ((err = mpz_add(r, r, m)) != SBN_OK)
				return err;
		}
	}
	return SBN_OK;
}

/* ---------------------------- assignment ---------------------------------- */

/* Set z = 0
 * Note: not GMP compatible */
int mpz_setzero(mpz_ptr z)
{
	z->s = 0;
	return mpz_zero_realloc(z, 0);
}

/* assign 's' to 'd'.
 * 's' can be statically allocated */
int mpz_set(mpz_ptr d, mpz_ptr s)
{
	int err;

	if ((err = mpz_zero_realloc(d, s->l)) != SBN_OK)
		return err;
	memcpy(d->d, s->d, s->l*MPZ_ATOMSZ);
	d->l = s->l;
	d->s = s->s;
	return SBN_OK;
}

/* Like mpz_set() without reallocation. Assume there is enough
 * space in d to get the value of s */
#define _mpz_set(D, S) \
do { \
	memcpy(D->d, S->d, S->l*MPZ_ATOMSZ); \
	D->l = S->l; \
	D->s = S->s; \
} while(0)

/* Set in 'z' the 32bit unsigned integer given as argument */
int mpz_set_ui(mpz_ptr z, u_int32_t u)
{
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	return mpz_set(z, mpz);
}

/* Set in 'z' the double d */
int mpz_set_d(mpz_ptr z, double d)
{
	int i = 0;
	u_int64_t u;

	z->s = (d < 0);
	d = (d < 0) ? -d : d;
	u = d;

	if (mpz_realloc(z, 8))
		return 1;
	while(u) {
		z->d[i] = u & MPZ_MASK;
		u >>= MPZ_SHIFT;
		i++;
	}
	z->l = i;
	return 0;
}

/* Set in 'z' the 64bit unsigned integer 'u' */
int mpz_set_ui64(mpz_ptr z, u_int64_t u)
{
	int i = 0;

	z->s = 0;
	if (mpz_realloc(z, 8))
		return 1;
	while(u) {
		z->d[i] = u & MPZ_MASK;
		u >>= MPZ_SHIFT;
		i++;
	}
	z->l = i;
	return 0;
}

/* Set in 'z' the 64bit signed integer 's' */
int mpz_set_si64(mpz_ptr z, int64_t s)
{
	u_int64_t u;
	int sign = s < 0, err;

	u = (s > 0) ? s : -s;
	if ((err = mpz_set_ui64(z, u)) != SBN_OK)
		return err;
	z->s = sign;
	return err;
}

/* Set in 'z' the 32bit unsigned integer given as argument */
int mpz_set_si(mpz_ptr z, int32_t s)
{
	int neg = s < 0;
	int err;
	u_int32_t u = neg ? -s : s;
	mpz_t mpz;

	u32tompz(t,u,l);
	u32pack(mpz,t,l);
	if ((err = mpz_set(z, mpz)))
		return err;
	if (neg)
		_mpz_neg(z);
	return err;
}

/* set 'd' to ABS('s'). */
int mpz_abs(mpz_ptr d, mpz_ptr s)
{
	int err;

	if ((d != s) && ((err = mpz_set(d, s)) != SBN_OK))
		return err;
	_mpz_abs(d);
	return SBN_OK;
}

/* set 'd' to -'s' */
int mpz_neg(mpz_ptr d, mpz_ptr s)
{
	int err;

	if ((d != s) && ((err = mpz_set(d, s)) != SBN_OK))
		return err;
	_mpz_neg(d);
	return SBN_OK;
}

/* ----------------------- number theoretic functions ----------------------- */
/* Compute the GCD (greatest common divisor) for 'a' and 'b' using
 * the binary GCD algorithm.
 *
 * 'g' = GCD('|a|', '|b|')
 *
 * g, a, b can overlap (we anyway need to work on copies of a and b)
 * assume a > 0, b > 0. */
int mpz_gcd_raw(mpz_ptr g, mpz_ptr a, mpz_atom_t *b, u_int32_t l)
{
	u_int32_t maxi = MAX(a->l, l);
	mpz_t B, t;
	int err;

	/* we need to work on copies. */
	_mpz_clone_stack(a);
	_mpz_rawclone_stack(B, b, l);
	_mpz_abs(a);
	_mpz_abs(B);
	/* Reset 'g', prepare to accept up to maxi+1 atoms, set it to 1 */
	if ((err = mpz_zero_realloc(g, maxi)) != SBN_OK)
		return err;
	g->d[0] = 1; /* after the realloc call there is at least 1 atom */
	g->l = 1;

	/* The binary GCD algorithm */
	mpz_init(t);

	/* While even(a) and even(b) -> a=a/2 b=b/2 g=g*2; */
	while(_mpz_is_even(a) && _mpz_is_even(B)) {
		_mpz_self_rshift1(a);
		_mpz_self_rshift1(B);
		_mpz_self_lshift1(g);
	}
	/* While a > 0 */
	while(_mpz_nonzero(a)) {
		/* While even(a) a=a/2 */
		while(_mpz_is_even(a))
			_mpz_self_rshift1(a);
		/* While even(b) b=b/2 */
		while(_mpz_is_even(B))
			_mpz_self_rshift1(B);
		/* t = abs(a-b)/2
		 * if (a >= b) a = t else b = t */
		if (mpz_cmpabs(a, B) >= 0) {
			if ((err = mpz_subi_raw(t, a, B->d, B->l)) != SBN_OK)
				goto err;
			_mpz_self_rshift1(t);
			_mpz_set(a, t);
		} else {
			if ((err = mpz_subi_raw(t, B, a->d, a->l)) != SBN_OK)
				goto err;
			_mpz_self_rshift1(t);
			_mpz_set(B, t);
		}
	}
	/* GCD = g * b */
	mpz_muli_raw(g, g, B->d, B->l);
	err = SBN_OK;
	/* fall through */
err:
	mpz_clear(t);
	return err;
}

/* wrapper for mpz_gcd_raw(). set GCD(a, 0) = a */
int mpz_gcd(mpz_ptr g, mpz_ptr a, mpz_ptr b)
{
	int err;

	if (_mpz_iszero(a)) {
		if ((err = mpz_set(g, b)) != SBN_OK)
			return err;
		_mpz_abs(g);
		return SBN_OK;
	}
	if (_mpz_iszero(b)) {
		if ((err = mpz_set(g, a)) != SBN_OK)
			return err;
		_mpz_abs(g);
		return SBN_OK;
	}
	return mpz_gcd_raw(g, a, b->d, b->l);
}

/* GCD(a, b) with b unsigned 32bit integer immediate.
 * if 'g' is not NULL the result is stored in g.
 * if 'g' is NULL and the result fits inside the u_int32_t type
 * it is returned. If the result doesn't fit (can happen only if b = 0)
 * 0 is returned. */
u_int32_t mpz_gcd_ui(mpz_ptr g, mpz_ptr a, u_int32_t b)
{
	g = g;
	a = a;
	b = b;
	return SBN_OK;
}

/* ----------------------- to/from string conversion ------------------------ */

#define sbn_chartoval(c) (r_cset[tolower(c)])
#define sbn_valtochar(v) (cset[v])

/* Extimate the number of bytes needed to store a string rappresentation
 * in base 'b' of the number 'z'. The length is overstimated, assuming
 * the precision of the C-lib log() is of 6 digits over the dot.
 * the length of the minus sign and the nul term are not included */
size_t mpz_sizeinbase(mpz_ptr z, u_int32_t b)
{
	double len;

	if (b < SBN_MINBASE || b > SBN_MAXBASE)
		return SBN_INVAL;
	len = ((basetable[b]+0.000001) * z->l) + 1;
	return (size_t) len;
}

/* Convert an mpz_t to a string rappresentation in base 'b'
 * Always nul-terminate the string if l > 0.
 *
 * We use a common trick to speed-up the conversion.
 * Instead to perform divisions with remainder between
 * the bignum and the specified base, we use a base that's
 * the biggest power of the real base. Then we use the CPU
 * division to divide by the real base. This limits a lot
 * the number of multi-precision divisions, that are slow.
 *
 * For example converting in base 10, every 10 divisions
 * 9 are divisions between two mpz_atom_t vars, and only
 * one between a bignum and an mpz_atom_t.
 *
 * TODO: Note that this is still not very good since we should
 * at least handle the case of a base that's power of 2
 * in a special way (i.e. performing shiftings and bitwise
 * andings). */
int mpz_tostr(mpz_ptr z, u_int32_t b, void *s, size_t l)
{
	mpz_t t;
	char *d = s, *p;
	mpz_atom_t hb, hbn;

	if (b < SBN_MINBASE || b > SBN_MAXBASE)
		return SBN_INVAL;
	if (!l)
		return SBN_OK;
	/* Handle z = 0 */
	if (_mpz_iszero(z)) {
		*d++ = '0';
		goto done;
	}
	/* get the biggest power of 'b' that fits in an mpz_atom_t
	 * and it's exponent from the table. */
	hbn = basepowtable[b].maxexp;
	hb = basepowtable[b].maxpow;
	l--;
	mpz_init(t);
	mpz_set(t, z);
	while(_mpz_nonzero(t) && l) {
		unsigned int i;
		mpz_atom_t x;
		x = _mpz_selfdiv1_qr_raw(t, (mpz_atom_t) hb);
		for (i = 0; (i < hbn) && (l != 0); i++) {
			*d++ = sbn_valtochar(x % b);
			x /= b;
			if (x == 0 && _mpz_iszero(t))
				break;
		}
	}
	mpz_clear(t);
done:
	/* add the sign if needed */
	if (l && z->s)
		*d++ = '-';
	*d-- = '\0';
	/* reverse the result */
	p = s;
	while(p < d) {
		char t;

		t = *p;
		*p = *d;
		*d = t;
		d--;
		p++;
	}
	return SBN_OK;
}

char *mpz_get_str(char *str, int b, mpz_ptr z)
{
	size_t len;

	if (b < SBN_MINBASE || b > SBN_MAXBASE)
		return NULL;

	len = mpz_sizeinbase(z, b) + 2;
	if (!str && ((str = malloc(len)) == NULL))
		return NULL;
	mpz_tostr(z, b, str, len);
	return str;
}

/* set in 'z' the ascii rappresentation in 's' of the number in base 'b'
 *
 * On error the original value of 'z' is not guaranteed to be the same
 * as before this function is called.
 *
 * Again possible optimizations are not implemented. Most notably
 * the base power of 2 case.
 */
int mpz_set_str(mpz_ptr z, char *s, int b)
{
	size_t len = strlen(s);
	char *t = s + len - 1;
	int neg = 0, err;
	mpz_t pow, toadd;

	/* seek the first non-blank char from the head */
	while(*s && isspace(*s)) {
		s++;
		len--;
	}
	/* check if the number is negative */
	if (len && *s == '-') {
		neg = 1;
		s++;
		len--;
	}
	/* guess the base */
	if (b == 0) {
		b = 10;
		if (len && *s == '0') {
			b = 8;
			s++;
			len--;
			if (len && tolower(*s) == 'x') {
				b = 16;
				s++;
				len--;
			} else if (len && tolower(*s) == 'b') {
				b = 2;
				s++;
				len--;
			}
		}
	}
	if (b < SBN_MINBASE || b > SBN_MAXBASE)
		return SBN_INVAL;
	/* seek the first non-blank char from the tail */
	while(t > s && isspace(*t))
		t--;
	/* convert it */
	mpz_init(pow);
	mpz_init(toadd);
	mpz_zero(z);
	if ((err = mpz_set_ui(pow, 1)) != SBN_OK)
		return err;
	while(t >= s) {
		int digit;

		digit = sbn_chartoval(*t);
		if (digit < 0 || digit >= b) {
			err = SBN_INVAL;
			goto error;
		}
		mpz_set_ui(toadd, digit);
		if ((err = mpz_mul(toadd, toadd, pow)) != SBN_OK)
			goto error;
		if ((err = mpz_add(z, z, toadd)) != SBN_OK)
			goto error;
		if ((err = mpz_mul_ui(pow, pow, b)) != SBN_OK)
			goto error;
		t--;
	}
	z->s = neg;
	err = SBN_OK;
	/* fall through */
error:
	mpz_clear(pow);
	mpz_clear(toadd);
	return err;
}

/* ------------------------------- random numbers --------------------------- */

/* The rc4_sbox array is static, but this doesn't mean you can't use this
 * library with threads. To create a real context for every random
 * generation session is an overkill here */
static unsigned char rc4_sbox[256];
/* We want to start every time with the same seed. This is very
 * important when some random number trigger multi-precision operations
 * bugs. This flags is used to initialize the sbox the first time */
static int rc4_seedflag = 0;

/* Initialize the sbox with the numbers from 0 to 255 */
void sbn_rand_init(void)
{
	int i;

	rc4_seedflag = 1;
	for (i = 0; i < 256; i++)
		rc4_sbox[i] = i;
}

/* Re-seed the generator with user-provided bytes */
void sbn_seed(void *seed, size_t len)
{
	int i;
	unsigned char *s = (unsigned char*)seed;

	for (i = 0; i < len; i++)
		rc4_sbox[i&0xFF] ^= s[i];
	/* discard the first 256 bytes of output after the reseed */
	for (i = 0; i < 32; i++)
		(void) sbn_rand();
}

/* Generates a 32bit random number using an RC4-like algorithm */
u_int32_t sbn_rand(void)
{
	u_int32_t r = 0;
	unsigned char *rc = (unsigned char*) &r;
	static unsigned int i = 0, j = 0;
	unsigned int si, sj, x;

	/* initialization, only needed the first time */
	if (!rc4_seedflag)
		sbn_rand_init();
	/* generates 4 bytes of pseudo-random numbers using RC4 */
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

/* Generate a random number of at most 'len' atoms length.
 * If 'len' is negative the number will be negative of length abs(len) */
int mpz_random(mpz_ptr z, int32_t len)
{
	int i, err, sign = 0;

	if (len < 0) {
		sign = 1;
		len = -len;
	}
	if (!len)
		return mpz_setzero(z);
	if ((err = mpz_realloc(z, len-1)) != SBN_OK)
		return err;
	for (i = 0; i < len; i++)
		z->d[i] = sbn_rand() & MPZ_MASK;
	_mpz_normalize(z);
	z->s = sign;
	return SBN_OK;
}

/* Convert the bignum to approsimated double */
double mpz_get_d(mpz_ptr z)
{
	double d = 0;
	u_int32_t l = z->l;

	while(l--)
		d = z->d[l] + d*MPZ_BASE;
	if (z->s)
		d = -d;
	return d;
}
