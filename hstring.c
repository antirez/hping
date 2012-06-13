/* hstring.c - Random string-related functions for hping.
 * Copyright(C) 2003 Salvatore Sanfilippo
 * All rights reserved */

/* $Id: hstring.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <sys/types.h>
#include <string.h>
#include <ctype.h>

/* return 1 if the string looks like an integer number
 * otherwise 0 is returned.
 *
 * this function is equivalent to this regexp:
 *		[:space:]*-{0,1}[0-9]+[:space:]*
 * in english:
 *  (0-inf spaces)(zero or one -)(1-inf digits)(0-inf spaces)
 */
int strisnum(char *s)
{
	int digits = 0; /* used to return false if there aren't digits */

	while(isspace(*s))
		s++; /* skip initial spaces */
	if (*s == '-') /* negative number? */
		s++;
	while(*s) {
		if (isspace(*s)) { /* skip spaces in the tail */
			while(isspace(*s))
				s++;
			if (*s) return 0; /* but don't allow other tail chars */
			return digits ? 1 : 0;
		}
		if (!isdigit(*s))
			return 0;
		s++;
		digits++;
	}
	return digits ? 1 : 0;
}

/* function similar to strtok() more convenient when we know the
 * max number of tokens, to tokenize with a single call.
 * Unlike strtok(), strftok() is thread safe.
 *
 * ARGS:
 *   'sep' is a string that contains all the delimiter characters
 *   'str' is the string to tokenize, that will be modified
 *   'tptrs' is an array of char* poiters that will contain the token pointers
 *   'nptrs' is the length of the 'tptrs' array.
 *
 * RETURN VALUE:
 *   The number of extracted tokens is returned.
 */
size_t strftok(char *sep, char *str, char **tptrs, size_t nptrs)
{
	size_t seplen = strlen(sep);
	size_t i, j = 0;
	int inside = 0;

	while(*str) {
		for(i = 0; i < seplen; i++) {
			if (sep[i] == *str)
				break;
		}
		if (i == seplen) { /* no match */
			if (!inside) {
				tptrs[j++] = str;
				inside = 1;
			}
		} else { /* match */
			if (inside) {
				*str = '\0';
				if (j == nptrs)
					return j;
				inside = 0;
			}
		}
		str++;
	}
	return j;
}
