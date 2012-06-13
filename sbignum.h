/* Sbignum.h -- antirez's arbitrary precision integer math library header file.
 * Copyright(C) 2002-2003 Salvatore Sanfilippo.
 * All rights reserved.
 *
 * $Id: sbignum.h,v 1.4 2004/06/04 07:22:38 antirez Exp $
 */

#ifndef _SBIGNUM_H
#define _SBIGNUM_H

#include <sys/types.h>
#include "fixtypes.h"

#define ATOMBYTES 4

/* The number internal rappresentation is an array of mpz_atom_t WORDS.
 * Every byte is a digit in base MPZ_AND+1, the first word is the least
 * significant word and so on */
#if ATOMBYTES == 4
typedef u_int32_t mpz_atom_t;
typedef u_int64_t mpz_carry_t;
typedef int64_t mpz_scarry_t;
#elif ATOMBYTES == 2
typedef u_int16_t mpz_atom_t;
typedef u_int32_t mpz_carry_t;
typedef int32_t mpz_scarry_t;
#elif ATOMBYTES == 1
typedef u_int8_t mpz_atom_t;
typedef u_int32_t mpz_carry_t;
typedef int32_t mpz_scarry_t;
#else
#error "Please define ATOMBYTES"
#endif

#define ATOMBITS (ATOMBYTES*8)

#define MPZ_ATOMSZ (sizeof(mpz_atom_t))
#define MPZ_MASK   ((mpz_atom_t)(~0))
#define MPZ_SHIFT  (MPZ_ATOMSZ*8)
#define MPZ_BASE   ((mpz_carry_t)MPZ_MASK+1)

struct struct_sbnz {
	mpz_atom_t *d;	/* data the least significant word is d[0] */
	u_int32_t a;	/* allocated bytes */
	u_int32_t l;	/* number of used bytes */
	u_int32_t s;	/* sign. non-zero if negative */
};
/* define the sbnz type */
typedef struct struct_sbnz *mpz_ptr;
typedef struct struct_sbnz mpz_t[1];

/* Error codes */
enum sbn_err {
	SBN_OK = 0,
	SBN_MEM,
	SBN_INVAL
};

#define SBN_MINBASE	2
#define SBN_MAXBASE	36

/* Exported macros */

/* this macro is true if z == 0 */
#define _mpz_iszero(z) ((z)->l == 0)

/* this is just the reverse. Equivalent to !_mpz_iszero */
#define _mpz_nonzero(z) ((z)->l != 0)

#define mpz_inc(z)	mpz_add_ui(z, z, 1)
#define mpz_dec(z)	mpz_sub_ui(z, z, 1)

/* ----------------------- Functions prototypes ----------------------------- */

/* inititialization/allocation */
void	mpz_init(mpz_ptr z);
void	mpz_clear(mpz_ptr z);
int	mpz_realloc(mpz_ptr z, u_int32_t i);
/* shifting */
int	mpz_lshift(mpz_ptr r, mpz_ptr z, u_int32_t i);
int	mpz_rshift(mpz_ptr r, mpz_ptr z, u_int32_t i);
/* comparision */
int32_t	mpz_abscmp(mpz_ptr a, mpz_ptr b);
int32_t mpz_abscmp_ui(mpz_ptr a, u_int32_t u);
int32_t mpz_cmp(mpz_ptr a, mpz_ptr b);
#define mpz_eq(a,b) (mpz_cmp(a,b) == 0)
#define mpz_noteq(a,b) (mpz_cmp(a,b) != 0)
#define mpz_lt(a,b) (mpz_cmp(a,b) < 0)
#define mpz_le(a,b) (mpz_cmp(a,b) <= 0)
#define mpz_gt(a,b) (mpz_cmp(a,b) > 0)
#define mpz_ge(a,b) (mpz_cmp(a,b) >= 0)
int32_t mpz_cmp_ui(mpz_ptr a, u_int32_t u);
int32_t mpz_cmp_si(mpz_ptr a, int32_t s);
#define mpz_eq_si(a,s) (mpz_cmp_si(a,s) == 0)
#define mpz_noteq_si(a,s) (mpz_cmp_si(a,s) != 0)
#define mpz_lt_si(a,s) (mpz_cmp_si(a,s) < 0)
#define mpz_le_si(a,s) (mpz_cmp_si(a,s) <= 0)
#define mpz_gt_si(a,s) (mpz_cmp_si(a,s) > 0)
#define mpz_ge_si(a,s) (mpz_cmp_si(a,s) >= 0)
/* addition */
int	mpz_add_ui(mpz_ptr r, mpz_ptr z, u_int32_t u);
int	mpz_add_si(mpz_ptr r, mpz_ptr z, int32_t s);
int	mpz_add(mpz_ptr r, mpz_ptr a, mpz_ptr b);
/* subtraction */
int	mpz_sub_ui(mpz_ptr r, mpz_ptr z, u_int32_t u);
int	mpz_sub_si(mpz_ptr r, mpz_ptr z, int32_t s);
int	mpz_sub(mpz_ptr r, mpz_ptr a, mpz_ptr b);
/* multiplication */
int	mpz_mul(mpz_ptr r, mpz_ptr z, mpz_ptr f);
int	mpz_mul_ui(mpz_ptr r, mpz_ptr z, u_int32_t u);
int	mpz_mul_si(mpz_ptr r, mpz_ptr z, int32_t s);
int	mpz_fac_ui(mpz_ptr r, u_int32_t i);
/* exponentialization */
int	mpz_powm(mpz_ptr r, mpz_ptr b, mpz_ptr e, mpz_ptr m);
int	mpz_pow(mpz_ptr r, mpz_ptr b, mpz_ptr e);
/* division */
int	mpz_tdiv_qr(mpz_ptr q, mpz_ptr r, mpz_ptr z, mpz_ptr d);
int	mpz_tdiv_qr_ui(mpz_ptr q, mpz_ptr r, mpz_ptr z, u_int32_t u);
int	mpz_tdiv_qr_si(mpz_ptr q, mpz_ptr r, mpz_ptr z, int32_t s);
int	mpz_tdiv_q(mpz_ptr q, mpz_ptr z, mpz_ptr d);
int	mpz_tdiv_q_ui(mpz_ptr q, mpz_ptr z, u_int32_t u);
int	mpz_tdiv_q_si(mpz_ptr q, mpz_ptr z, int32_t s);
int	mpz_tdiv_r(mpz_ptr r, mpz_ptr z, mpz_ptr d);
int	mpz_tdiv_r_ui(mpz_ptr r, mpz_ptr z, u_int32_t u);
int	mpz_tdiv_r_si(mpz_ptr r, mpz_ptr z, int32_t s);
int	mpz_mod(mpz_ptr r, mpz_ptr z, mpz_ptr m);
/* root extraction */
int	mpz_sqrt(mpz_ptr r, mpz_ptr z);
/* assignment */
int	mpz_setzero(mpz_ptr z);
int	mpz_set(mpz_ptr d, mpz_ptr s);
int	mpz_set_ui(mpz_ptr z, u_int32_t u);
int	mpz_set_si(mpz_ptr z, int32_t s);
int	mpz_abs(mpz_ptr d, mpz_ptr s);
int	mpz_neg(mpz_ptr d, mpz_ptr s);
/* bit operations */
u_int32_t mpz_bits(mpz_ptr z);
int	mpz_setbit(mpz_ptr z, u_int32_t i);
int	mpz_clrbit(mpz_ptr z, u_int32_t i);
int	mpz_testbit(mpz_ptr z, u_int32_t i);
/* number theoretic functions */
int	mpz_gcd(mpz_ptr g, mpz_ptr a, mpz_ptr b);
u_int32_t mpz_gcd_ui(mpz_ptr g, mpz_ptr a, u_int32_t b);
/* to/from mpz conversions */
size_t mpz_sizeinbase(mpz_ptr z, u_int32_t b);
char	*mpz_get_str(char *str, int b, mpz_ptr z);
int	mpz_set_str(mpz_ptr z, char *s, int b);
double	mpz_get_d(mpz_ptr z);
int	mpz_set_d(mpz_ptr z, double d);
int	mpz_set_si64(mpz_ptr z, int64_t s);
int	mpz_set_ui64(mpz_ptr z, u_int64_t u);
/* random numbers */
u_int32_t sbn_rand(void);
void	sbn_seed(void *seed, size_t len);
int	mpz_random(mpz_ptr z, int32_t len);

#endif /* _SBIGNUM_H */
