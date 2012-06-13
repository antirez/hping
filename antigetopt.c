/* antigetopt -- a getopt replacement
 * Copyright(C) 2001 Salvatore Sanfilippo <antirez@invece.org>
 * This software is released under the GPL license
 * see the COPYING file for more information */

/* $Id: antigetopt.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

/* TODO:
 * argument list sanity check */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "antigetopt.h"

/* global vars */
char *ago_optarg = NULL;
char *ago_optname = NULL;
char ago_optchar = '\0';

/* static vars */
static struct ago_exception {
	int (*tester)(void);
	char *msg;
} ago_exceptions[3] = {
	{ NULL, NULL },
	{ NULL, NULL },
	{ NULL, NULL }
};

static int ago_exception_bits[] = { AGO_EXCEPT0, AGO_EXCEPT1, AGO_EXCEPT2 };

/* static functions */
static struct ago_optlist
*ago_lookup(struct ago_optlist *list, char *arg, int *islong, int *amb);
static int strinitcmp(char *a, char *b);

/*----------------------------- implementation ------------------------------ */

int antigetopt(int argc, char **argv, struct ago_optlist *list)
{
	static char **save_argv = NULL;
	static char *chain = NULL;
	static int endoptions = 0;
	struct ago_optlist *opt;
	int islong;

	/* Reset */
	if (argv == NULL) {
		save_argv = NULL;
		chain = NULL;
		endoptions = 0;
		return AGO_RESET;
	} else {
		if (save_argv == NULL) {
			save_argv = argv+1; /* skips the argv[0] */
			/* XXX: argument list sanity check */
		}
	}

chain_start:
	if (chain) {
		if (*chain == '\0')
			chain = NULL;
		else {
			if ((opt = ago_lookup(list, chain, &islong, NULL))
			    == NULL)
				return AGO_UNKNOWN;
			if (!(opt->ao_flags & AGO_NOARG)) {
				/* the if expression maybe false if the
				 * argument is optional */
				if (chain[1] == '\0' && *save_argv)
					ago_optarg = *save_argv++;
				/* while it is mandatory for the NEEDARG type */
				else if (opt->ao_flags & AGO_NEEDARG)
					return AGO_REQARG;
			}
			chain++;
			return opt->ao_id;
		}
	}

	argv = save_argv;

	/* handle the "--" special option */
	if (*argv && strcmp(*argv, "--") == 0) {
		endoptions = 1;
		argv++;
		save_argv++;
	}

	while(*argv) {
		/* The option must start with '-' */
		if (!endoptions && argv[0][0] == '-' && argv[0][1] != '\0') {
			int amb;

			/* note: ago_lookup also sets ago_optname */
			if ((opt = ago_lookup(list, argv[0], &islong, &amb))
			    == NULL)
				return amb ? AGO_AMBIG : AGO_UNKNOWN;

			/* handle the collapsed short options */
			if (!islong && argv[0][2] != '\0') {
				chain = argv[0]+1;
				save_argv++;
				goto chain_start;
			}

			/* if the option require or may have an argument */
			ago_optarg = NULL;
			/* If the argument is needed we get the next argv[]
			 * element without care about what it contains */
			if (opt->ao_flags & AGO_NEEDARG) {
				if (argv[1] == NULL)
					return AGO_REQARG;
				ago_optarg = argv[1];
				argv++;
			}
			/* If the argument is optional we only recognize it
			 * as argument if it does not starts with '-' */
			else if (opt->ao_flags & AGO_OPTARG) {
				if (argv[1] && argv[1][0] != '-') {
					ago_optarg = argv[1];
					argv++;
				}
			}
			save_argv = argv+1;
			return opt->ao_id;
		} else {
			save_argv = argv+1;
			ago_optarg = argv[0];
			ago_optchar = '\0';
			ago_optname = NULL;
			return AGO_ALONE;
		}
	}
	return AGO_EOF;
}

#define UNK_SHORT_ERRSTRING "invalid option -- %c\n"
#define UNK_LONG_ERRSTRING "unrecognized option `--%s'\n"
#define ARG_SHORT_ERRSTRING "option requires an argument -- %c\n"
#define ARG_LONG_ERRSTRING "option `--%s' requires an argument\n"
#define AMB_ERRSTRING "option `--%s' is ambiguos\n"
#define IERR_ERRSTRING "internal error. ago_gnu_error() called with " \
			   "a bad error code (%d)\n"
void ago_gnu_error(char *pname, int error)
{
	if (pname)
		fprintf(stderr, "%s: ", pname);
	switch(error) {
		case AGO_UNKNOWN:
			if (ago_optname)
				fprintf(stderr, UNK_LONG_ERRSTRING,
						ago_optname);
			else
				fprintf(stderr, UNK_SHORT_ERRSTRING,
						ago_optchar);
			break;
		case AGO_REQARG:
			if (ago_optname)
				fprintf(stderr, ARG_LONG_ERRSTRING,
						ago_optname);
			else
				fprintf(stderr, ARG_SHORT_ERRSTRING,
						ago_optchar);
			break;
		case AGO_AMBIG:
			fprintf(stderr, AMB_ERRSTRING, ago_optname);
			break;
		default:
			fprintf(stderr, IERR_ERRSTRING, error);
			break;
	}
}

int ago_set_exception(int except_nr, int (*tester)(void), char *msg)
{
	if (tester == NULL || msg == NULL || except_nr < 0 || except_nr >= 3)
		return -1;
	ago_exceptions[except_nr].tester = tester;
	ago_exceptions[except_nr].msg = msg;
	return 0;
}

/*-------------------------- static functions ------------------------------- */

struct ago_optlist
*ago_lookup(struct ago_optlist *list, char *arg, int *islong, int *amb)
{
	int i;

	/* ago_lookup can be receive as `arg' a pointer to a
	 * long argument, like --option, a pointer to a short
	 * argument like -O, or just a pointer to a char sequence
	 * in the case of collapsed short arguments like -abcde. */

	/* Clear the 'ambiguos' flag, used to report the caller
	 * an ambiguos option abbreviation error */
	if (amb) *amb = 0;

	if (*arg == '-') /* skips the first - if any */
		arg++;

	switch(*arg) {
	case '\0':
		return NULL;
	case '-':
		*islong = 1;
		arg++; /* skip the last - */
		break;
	default:
		*islong = 0;
		break;
	}

	/* search the argument in the list */
	if (*islong) {
		int retval;
		struct ago_optlist *last = NULL;

		while(!(list->ao_flags & AGO_ENDOFLIST)) {
			ago_optname = arg;
			ago_optchar = '\0';
			if ((retval = strinitcmp(arg, list->ao_long)) != 0) {
				switch(retval) {
				case 1:
					if (last) {
						if (amb) *amb = 1;
						return NULL;
					}
					last = list;
					break;
				case 2:
					goto ok;
				}
			}
			list++;
		}
		if (last) {
			ago_optname = last->ao_long;
			list = last;
			goto ok;
		}
	} else {
		ago_optchar = *arg;
		ago_optname = NULL;
		while(!(list->ao_flags & AGO_ENDOFLIST)) {
			if (*arg == list->ao_short)
				goto ok;
			list++;
		}
	}
	return NULL;
ok:
	/* handle the exceptions if any */
	for (i = 0; i < 3; i++) {
		if ((list->ao_flags & ago_exception_bits[i]) &&
		    ago_exceptions[i].tester)
		{
			if (ago_exceptions[i].tester()) {
				if (ago_optname) {
					fprintf(stderr, "%s `--%s'\n",
						ago_exceptions[i].msg,
						ago_optname);
				} else {
					fprintf(stderr, "%s `-%c'\n",
						ago_exceptions[i].msg,
						ago_optchar);
				}
				exit(1);
			}
		}
	}
	return list;
}

/* Given two strings this function returns:
 * 1, if the strings are the same for the len of the first string (abc, abcde)
 * 2, if the strings are exactly the same: (abcd, abcd)
 * otherwise zero is returned (abcde, abcd) ... (djf, 293492) */
int strinitcmp(char *a, char *b)
{
	if (!a || !b)
		return 0;
	while (*a && *b) {
		if (*a != *b)
			return 0;
		a++; b++;
	}
	if (*a)
		return 0;
	if (*a == *b)
		return 2;
	return 1;
}
