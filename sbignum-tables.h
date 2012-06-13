#ifndef _SBN_TABLES_H
#define _SBN_TABLES_H

#include <sys/types.h>

extern char *cset;
extern int8_t r_cset[256];
extern int8_t bitstable[256];
extern double basetable[37];
struct sbn_basepow {
	unsigned long maxpow;
	unsigned long maxexp;
};
extern struct sbn_basepow basepowtable[37];

#endif /* _SBN_TABLES_H */
