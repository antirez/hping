#include "sbignum-tables.h"
#include "sbignum.h"

/* maps a number to a char */
char *cset = "0123456789abcdefghijklmnopqrstuvwxyz";

/* maps a char to a number */
int8_t r_cset[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 
};

/* bitstable[n] is the number of set bits
 * in the number 'n' */
int8_t bitstable[256] = {
	0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
	4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8, 
};

/* basetable[b] = number of digits needed to convert
 * an mpz atom in base 'b' */
#if ATOMBYTES == 1
double basetable[37] = {
	0, /* unused */
	0, /* unused */
	8.000000, /* (log of 2 in base 256) */
	5.047438, /* (log of 3 in base 256) */
	4.000000, /* (log of 4 in base 256) */
	3.445412, /* (log of 5 in base 256) */
	3.094822, /* (log of 6 in base 256) */
	2.849657, /* (log of 7 in base 256) */
	2.666667, /* (log of 8 in base 256) */
	2.523719, /* (log of 9 in base 256) */
	2.408240, /* (log of 10 in base 256) */
	2.312519, /* (log of 11 in base 256) */
	2.231544, /* (log of 12 in base 256) */
	2.161905, /* (log of 13 in base 256) */
	2.101196, /* (log of 14 in base 256) */
	2.047664, /* (log of 15 in base 256) */
	2.000000, /* (log of 16 in base 256) */
	1.957204, /* (log of 17 in base 256) */
	1.918500, /* (log of 18 in base 256) */
	1.883271, /* (log of 19 in base 256) */
	1.851026, /* (log of 20 in base 256) */
	1.821362, /* (log of 21 in base 256) */
	1.793951, /* (log of 22 in base 256) */
	1.768518, /* (log of 23 in base 256) */
	1.744834, /* (log of 24 in base 256) */
	1.722706, /* (log of 25 in base 256) */
	1.701968, /* (log of 26 in base 256) */
	1.682479, /* (log of 27 in base 256) */
	1.664117, /* (log of 28 in base 256) */
	1.646775, /* (log of 29 in base 256) */
	1.630360, /* (log of 30 in base 256) */
	1.614793, /* (log of 31 in base 256) */
	1.600000, /* (log of 32 in base 256) */
	1.585919, /* (log of 33 in base 256) */
	1.572493, /* (log of 34 in base 256) */
	1.559672, /* (log of 35 in base 256) */
	1.547411, /* (log of 36 in base 256) */
};
#endif

#if ATOMBYTES == 2
double basetable[37] = {
	0, /* unused */
	0, /* unused */
	16.000000, /* (log of 2 in base 65536) */
	10.094876, /* (log of 3 in base 65536) */
	8.000000, /* (log of 4 in base 65536) */
	6.890825, /* (log of 5 in base 65536) */
	6.189645, /* (log of 6 in base 65536) */
	5.699315, /* (log of 7 in base 65536) */
	5.333333, /* (log of 8 in base 65536) */
	5.047438, /* (log of 9 in base 65536) */
	4.816480, /* (log of 10 in base 65536) */
	4.625037, /* (log of 11 in base 65536) */
	4.463087, /* (log of 12 in base 65536) */
	4.323810, /* (log of 13 in base 65536) */
	4.202393, /* (log of 14 in base 65536) */
	4.095328, /* (log of 15 in base 65536) */
	4.000000, /* (log of 16 in base 65536) */
	3.914409, /* (log of 17 in base 65536) */
	3.836999, /* (log of 18 in base 65536) */
	3.766543, /* (log of 19 in base 65536) */
	3.702051, /* (log of 20 in base 65536) */
	3.642724, /* (log of 21 in base 65536) */
	3.587901, /* (log of 22 in base 65536) */
	3.537036, /* (log of 23 in base 65536) */
	3.489669, /* (log of 24 in base 65536) */
	3.445412, /* (log of 25 in base 65536) */
	3.403937, /* (log of 26 in base 65536) */
	3.364959, /* (log of 27 in base 65536) */
	3.328234, /* (log of 28 in base 65536) */
	3.293549, /* (log of 29 in base 65536) */
	3.260721, /* (log of 30 in base 65536) */
	3.229585, /* (log of 31 in base 65536) */
	3.200000, /* (log of 32 in base 65536) */
	3.171838, /* (log of 33 in base 65536) */
	3.144986, /* (log of 34 in base 65536) */
	3.119344, /* (log of 35 in base 65536) */
	3.094822, /* (log of 36 in base 65536) */
};
#endif

#if ATOMBYTES == 4
double basetable[37] = {
	0, /* unused */
	0, /* unused */
	32.000000, /* (log of 2 in base 4294967296) */
	20.189752, /* (log of 3 in base 4294967296) */
	16.000000, /* (log of 4 in base 4294967296) */
	13.781650, /* (log of 5 in base 4294967296) */
	12.379290, /* (log of 6 in base 4294967296) */
	11.398630, /* (log of 7 in base 4294967296) */
	10.666667, /* (log of 8 in base 4294967296) */
	10.094876, /* (log of 9 in base 4294967296) */
	9.632960, /* (log of 10 in base 4294967296) */
	9.250074, /* (log of 11 in base 4294967296) */
	8.926174, /* (log of 12 in base 4294967296) */
	8.647621, /* (log of 13 in base 4294967296) */
	8.404785, /* (log of 14 in base 4294967296) */
	8.190657, /* (log of 15 in base 4294967296) */
	8.000000, /* (log of 16 in base 4294967296) */
	7.828817, /* (log of 17 in base 4294967296) */
	7.673999, /* (log of 18 in base 4294967296) */
	7.533085, /* (log of 19 in base 4294967296) */
	7.404103, /* (log of 20 in base 4294967296) */
	7.285448, /* (log of 21 in base 4294967296) */
	7.175802, /* (log of 22 in base 4294967296) */
	7.074071, /* (log of 23 in base 4294967296) */
	6.979337, /* (log of 24 in base 4294967296) */
	6.890825, /* (log of 25 in base 4294967296) */
	6.807874, /* (log of 26 in base 4294967296) */
	6.729917, /* (log of 27 in base 4294967296) */
	6.656467, /* (log of 28 in base 4294967296) */
	6.587099, /* (log of 29 in base 4294967296) */
	6.521442, /* (log of 30 in base 4294967296) */
	6.459171, /* (log of 31 in base 4294967296) */
	6.400000, /* (log of 32 in base 4294967296) */
	6.343676, /* (log of 33 in base 4294967296) */
	6.289972, /* (log of 34 in base 4294967296) */
	6.238689, /* (log of 35 in base 4294967296) */
	6.189645, /* (log of 36 in base 4294967296) */
};
#endif

/* basepowtable[b] = the first column is the biggest power of 'b'
 * that fits in mpz_atom_t, the second column is the exponent
 * 'e' so that b^e = the value of the first column */
#if ATOMBYTES == 1
struct sbn_basepow basepowtable[37] = {
	{0,0}, /* unused */
	{0,0}, /* unused */
	{128U, 7U}, /* floor(log of 2 in base 255) */
	{243U, 5U}, /* floor(log of 3 in base 255) */
	{64U, 3U}, /* floor(log of 4 in base 255) */
	{125U, 3U}, /* floor(log of 5 in base 255) */
	{216U, 3U}, /* floor(log of 6 in base 255) */
	{49U, 2U}, /* floor(log of 7 in base 255) */
	{64U, 2U}, /* floor(log of 8 in base 255) */
	{81U, 2U}, /* floor(log of 9 in base 255) */
	{100U, 2U}, /* floor(log of 10 in base 255) */
	{121U, 2U}, /* floor(log of 11 in base 255) */
	{144U, 2U}, /* floor(log of 12 in base 255) */
	{169U, 2U}, /* floor(log of 13 in base 255) */
	{196U, 2U}, /* floor(log of 14 in base 255) */
	{225U, 2U}, /* floor(log of 15 in base 255) */
	{16U, 1U}, /* floor(log of 16 in base 255) */
	{17U, 1U}, /* floor(log of 17 in base 255) */
	{18U, 1U}, /* floor(log of 18 in base 255) */
	{19U, 1U}, /* floor(log of 19 in base 255) */
	{20U, 1U}, /* floor(log of 20 in base 255) */
	{21U, 1U}, /* floor(log of 21 in base 255) */
	{22U, 1U}, /* floor(log of 22 in base 255) */
	{23U, 1U}, /* floor(log of 23 in base 255) */
	{24U, 1U}, /* floor(log of 24 in base 255) */
	{25U, 1U}, /* floor(log of 25 in base 255) */
	{26U, 1U}, /* floor(log of 26 in base 255) */
	{27U, 1U}, /* floor(log of 27 in base 255) */
	{28U, 1U}, /* floor(log of 28 in base 255) */
	{29U, 1U}, /* floor(log of 29 in base 255) */
	{30U, 1U}, /* floor(log of 30 in base 255) */
	{31U, 1U}, /* floor(log of 31 in base 255) */
	{32U, 1U}, /* floor(log of 32 in base 255) */
	{33U, 1U}, /* floor(log of 33 in base 255) */
	{34U, 1U}, /* floor(log of 34 in base 255) */
	{35U, 1U}, /* floor(log of 35 in base 255) */
	{36U, 1U}, /* floor(log of 36 in base 255) */
};
#endif

#if ATOMBYTES == 2
struct sbn_basepow basepowtable[37] = {
	{0,0}, /* unused */
	{0,0}, /* unused */
	{32768U, 15U}, /* floor(log of 2 in base 65535) */
	{59049U, 10U}, /* floor(log of 3 in base 65535) */
	{16384U, 7U}, /* floor(log of 4 in base 65535) */
	{15625U, 6U}, /* floor(log of 5 in base 65535) */
	{46656U, 6U}, /* floor(log of 6 in base 65535) */
	{16807U, 5U}, /* floor(log of 7 in base 65535) */
	{32768U, 5U}, /* floor(log of 8 in base 65535) */
	{59049U, 5U}, /* floor(log of 9 in base 65535) */
	{10000U, 4U}, /* floor(log of 10 in base 65535) */
	{14641U, 4U}, /* floor(log of 11 in base 65535) */
	{20736U, 4U}, /* floor(log of 12 in base 65535) */
	{28561U, 4U}, /* floor(log of 13 in base 65535) */
	{38416U, 4U}, /* floor(log of 14 in base 65535) */
	{50625U, 4U}, /* floor(log of 15 in base 65535) */
	{4096U, 3U}, /* floor(log of 16 in base 65535) */
	{4913U, 3U}, /* floor(log of 17 in base 65535) */
	{5832U, 3U}, /* floor(log of 18 in base 65535) */
	{6859U, 3U}, /* floor(log of 19 in base 65535) */
	{8000U, 3U}, /* floor(log of 20 in base 65535) */
	{9261U, 3U}, /* floor(log of 21 in base 65535) */
	{10648U, 3U}, /* floor(log of 22 in base 65535) */
	{12167U, 3U}, /* floor(log of 23 in base 65535) */
	{13824U, 3U}, /* floor(log of 24 in base 65535) */
	{15625U, 3U}, /* floor(log of 25 in base 65535) */
	{17576U, 3U}, /* floor(log of 26 in base 65535) */
	{19683U, 3U}, /* floor(log of 27 in base 65535) */
	{21952U, 3U}, /* floor(log of 28 in base 65535) */
	{24389U, 3U}, /* floor(log of 29 in base 65535) */
	{27000U, 3U}, /* floor(log of 30 in base 65535) */
	{29791U, 3U}, /* floor(log of 31 in base 65535) */
	{32768U, 3U}, /* floor(log of 32 in base 65535) */
	{35937U, 3U}, /* floor(log of 33 in base 65535) */
	{39304U, 3U}, /* floor(log of 34 in base 65535) */
	{42875U, 3U}, /* floor(log of 35 in base 65535) */
	{46656U, 3U}, /* floor(log of 36 in base 65535) */
};
#endif

#if ATOMBYTES == 4
struct sbn_basepow basepowtable[37] = {
	{0,0}, /* unused */
	{0,0}, /* unused */
	{2147483648U, 31U}, /* floor(log of 2 in base 4294967295) */
	{3486784401U, 20U}, /* floor(log of 3 in base 4294967295) */
	{1073741824U, 15U}, /* floor(log of 4 in base 4294967295) */
	{1220703125U, 13U}, /* floor(log of 5 in base 4294967295) */
	{2176782336U, 12U}, /* floor(log of 6 in base 4294967295) */
	{1977326743U, 11U}, /* floor(log of 7 in base 4294967295) */
	{1073741824U, 10U}, /* floor(log of 8 in base 4294967295) */
	{3486784401U, 10U}, /* floor(log of 9 in base 4294967295) */
	{1000000000U, 9U}, /* floor(log of 10 in base 4294967295) */
	{2357947691U, 9U}, /* floor(log of 11 in base 4294967295) */
	{429981696U, 8U}, /* floor(log of 12 in base 4294967295) */
	{815730721U, 8U}, /* floor(log of 13 in base 4294967295) */
	{1475789056U, 8U}, /* floor(log of 14 in base 4294967295) */
	{2562890625U, 8U}, /* floor(log of 15 in base 4294967295) */
	{268435456U, 7U}, /* floor(log of 16 in base 4294967295) */
	{410338673U, 7U}, /* floor(log of 17 in base 4294967295) */
	{612220032U, 7U}, /* floor(log of 18 in base 4294967295) */
	{893871739U, 7U}, /* floor(log of 19 in base 4294967295) */
	{1280000000U, 7U}, /* floor(log of 20 in base 4294967295) */
	{1801088541U, 7U}, /* floor(log of 21 in base 4294967295) */
	{2494357888U, 7U}, /* floor(log of 22 in base 4294967295) */
	{3404825447U, 7U}, /* floor(log of 23 in base 4294967295) */
	{191102976U, 6U}, /* floor(log of 24 in base 4294967295) */
	{244140625U, 6U}, /* floor(log of 25 in base 4294967295) */
	{308915776U, 6U}, /* floor(log of 26 in base 4294967295) */
	{387420489U, 6U}, /* floor(log of 27 in base 4294967295) */
	{481890304U, 6U}, /* floor(log of 28 in base 4294967295) */
	{594823321U, 6U}, /* floor(log of 29 in base 4294967295) */
	{729000000U, 6U}, /* floor(log of 30 in base 4294967295) */
	{887503681U, 6U}, /* floor(log of 31 in base 4294967295) */
	{1073741824U, 6U}, /* floor(log of 32 in base 4294967295) */
	{1291467969U, 6U}, /* floor(log of 33 in base 4294967295) */
	{1544804416U, 6U}, /* floor(log of 34 in base 4294967295) */
	{1838265625U, 6U}, /* floor(log of 35 in base 4294967295) */
	{2176782336U, 6U}, /* floor(log of 36 in base 4294967295) */
};
#endif

