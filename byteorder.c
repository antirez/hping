#if 0
#
# Compile with:
#	$sh byteorder.c
#
cc byteorder.c -o byteorder || exit 1
echo successfully compiled
exit
#endif /* 0 */

/* Coypright (C) 1999-2003 Salvatore Sanfilippo */

/*
 * 0.1 first version
 * 0.2 add Strchr, so it's possibile remove string.h
 * 0.3 more portable thx to Pancrazio De Mauro 'TrantIT'!!!
 * 0.4 better debug output
 */

/* $Id: byteorder.c,v 1.2 2003/09/01 00:22:06 antirez Exp $ */

#include <stdio.h>

char *Strchr(char *s, char c)
{
	while(*s)
		if (*s++ == c)
			return s;

	return (char*) 0;
}

int main(int argc, char **argv)
{
	unsigned int test = 1;
	unsigned char *x;
	int macro = 0, debug = 0, help = 0, j;

	for (j = 1; j < argc; j++) {
		if (Strchr(argv[j], 'm')) macro = 1;
		if (Strchr(argv[j], 'd')) debug = 1;
		if (Strchr(argv[j], 'h')) help = 1;
	}

	if (help) {
		printf(	"-m	macro output\n"
			"-d	debug\n"
			"-h	help\n");
		return 0;
	}
		
	x = (unsigned char*) &test;

	if (*x == 0x00) {
		if (macro)
			printf("__BIG_ENDIAN_BITFIELD\n");
		else
			printf("big endian\n");
	}
	else if (*x == 0x01) {
		if (macro)
			printf("__LITTLE_ENDIAN_BITFIELD\n");
		else
			printf("little endian\n");
	} else {
		printf("\nWARNING!!! byteorder exception\n\n");
		debug = 1;
	}

	if (debug) {
		printf("sizeof(unsigned int) = %d\n", sizeof(unsigned int));
		printf("unsigned int test = 1;\n");
		printf("in memory as: ");
		for (j = 0; j < sizeof(unsigned int); j++)
			printf("%02x ", x[j]);
		printf("\n");
	}
	return 0;
}
