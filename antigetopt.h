#ifndef __ANTIGETOPT_H
#define __ANTIGETOPT_H

/* special return codes */
enum { AGO_EOF=4000, AGO_ALONE, AGO_UNKNOWN, AGO_REQARG, AGO_RESET, AGO_AMBIG };

/* option flags */
#define AGO_NOARG (1<<0)		/* no argument */
#define AGO_NEEDARG (1<<1)		/* required argument */
#define AGO_OPTARG (1<<2)		/* optional argument */
#define AGO_EXCEPT0 (1<<3)		/* exception #0 */
#define AGO_EXCEPT1 (1<<4)		/* exception #1 */
#define AGO_EXCEPT2 (1<<5)		/* exception #3 */
#define AGO_ENDOFLIST (1<<15)		/* end of argument list marker */

/* option list null term */
#define AGO_LIST_TERM {'\0',NULL,0,AGO_ENDOFLIST}

/* The structure that defines an argument */
struct ago_optlist {
	char ao_short;
	char *ao_long;
	int ao_id;
	int ao_flags;
};

extern char *ago_optarg;
extern char *ago_optname;
extern char ago_optchar;

int	antigetopt(int argc, char **argv, struct ago_optlist *list);
void	ago_gnu_error(char *pname, int error);
int	ago_set_exception(int except_nr, int (*tester)(void), char *msg);

#endif /* __ANTIGETOPT_H */
