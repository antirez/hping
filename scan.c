/* Scanner mode for hping2
 * Copyright(C) 2003 Salvatore Sanfilippo
 * All rights reserved */

/* TODO:
 * an application-level aware UDP scanner.
 * add ICMP handling in replies.
 * The algorithm is far from be optimal, also there isn't a clear
 * way to delay smaller amounts of time then usleep(1) without
 * to use a dummy loop.
 * */

/* $Id: scan.c,v 1.3 2003/10/22 10:41:00 antirez Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#if 0
#include <sys/ipc.h>
#endif
#include <sys/shm.h>
#include <sys/sem.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <signal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>

#if 0
#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#else
/* according to X/OPEN we have to define it ourselves */
union semun {
	int val;                    /* value for SETVAL */
	struct semid_ds *buf;       /* buffer for IPC_STAT, IPC_SET */
	unsigned short int *array;  /* array for GETALL, SETALL */
	struct seminfo *__buf;      /* buffer for IPC_INFO */
};
#endif
#endif

#include "hping2.h"
#include "globals.h"
#include "hstring.h"

#define SEM_MODE 0777
#define MAXPORT 65535

int opt_scan_probes = 8;
float avrgms = 0;
int avrgcount = 0;

/* ---------------------------- data structures ----------------------------- */

/* Note that while we don't use any kind of locking, to access
 * this fields is safe. the 'retry' field is only accessed by the
 * sendinf half, while the 'active' field is set by the receiver
 * and tested by the sender so atomicity isn't an issue. */
struct portinfo {
	int active;
	int retry;
	time_t sentms; /* Upss... added this that requires locking, FIXME */
};

/* ------------------------- shared memory related -------------------------- */

static int id;	/* shared memory id */

static int shm_creat(int size)
{
	id = shmget(IPC_PRIVATE, size, IPC_CREAT | 0777);
	if (id == -1)
	{
		perror("[shm_creat] shmget");
		return -1; /* on error -1 */
	}
	return id; /* on success > 0 */
}

static void *shm_attach(void)
{
	void *shared;

	shared = shmat(id, 0, 0);
	if (shared == (void*) -1)
	{
		perror("[shm_attach] shmat");
		return NULL; /* on error NULL */
	}
	return shared; /* on success the address */
}

static int shm_rm(void)
{
	struct shmid_ds shmemds;

	return shmctl(id, IPC_RMID, &shmemds);
}

static int shm_detach(void *addr)
{
	return shmdt(addr);
}

static void *shm_init(int size)
{
	if (shm_creat(size) == -1)
		return NULL;
	return shm_attach();
}

static void shm_close(void *addr)
{
	shm_detach(addr);
	shm_rm();
}

/* ------------------------------ locking ---------------------------------- */

/* Note that a mutex can't be used with shared memory (on Linux), the only left
 * option is a semaphore, but I tried to protect the critical code
 * using the functions above: the scanner becomes too slow. For now
 * it's better to have nothing at all, for the future we need something
 * like a spinlock. (btw, note that the code should be safe on x86) */

/* I left this code here, just in the case it will be useful for testing */
#if 0
static int sem_init(void)
{
	int semid, sem_key;

	if ((sem_key = ftok("/tmp/hpingscansem", 1)) == -1) {
		perror("ftok");
		exit(1);
	}

	/* Semi-safe semaphore initialization from R.Stevens */

	/* Try to create the semaphore with EXCL */
	if ((semid = semget(sem_key, 1, IPC_CREAT|IPC_EXCL|SEM_MODE)) != -1) {
		/* success, we need to initialize it */
		union semun arg;

		arg.val = 1;
		if (semctl(semid, 0, SETVAL, arg) == -1) {
			perror("semctl");
			exit(1);
		}
	} else if (errno == EEXIST) {
		if ((semid = semget(sem_key, 1, SEM_MODE)) == -1) {
			perror("semget");
			exit(1);
		}
	} else {
		perror("semget");
		exit(1);
	}
	return semid;
}

static int ports_lock(int semid)
{
	struct sembuf op[1];

	op[0].sem_num = 0;
	op[0].sem_op = -1;
	op[0].sem_flg = SEM_UNDO;
	return semop(semid, op, 1);
}

static int ports_unlock(int semid)
{
	struct sembuf op[1];

	op[0].sem_num = 0;
	op[0].sem_op = +1;
	op[0].sem_flg = SEM_UNDO;
	return semop(semid, op, 1);
}
#endif

/* -------------------------------- misc ----------------------------------- */
static char *tcp_strflags(char *s, unsigned int flags)
{
	char *ftab = "FSRPAYXY", *p = s;
	int bit = 0;

	memset(s, '.', 8);
	s[8] = '\0';
	while(bit < 8) {
		if (flags & (1 << bit))
			p[bit] = ftab[bit];
		bit++;
	}
	return s;
}

static char *port_to_name(int port)
{
	struct servent *se;

	se = getservbyport(htons(port), NULL);
	if (!se)
		return "";
	else
		return se->s_name;
}

/* ----------------------------- ports parsing ------------------------------ */
static int parse_ports(struct portinfo *pi, char *ports)
{
	char *args[32], *p = strdup(ports);
	int argc, j, i;

	if (!p) {
		fprintf(stderr, "Out of memory");
		return 1;
	}
	argc = strftok(",", ports, args, 32);
	for (j = 0; j < argc; j++) {
		int neg = 0;
		char *a = args[j];

		/* ports negation */
		if (a[0] == '!') {
			neg = 1;
			a++;
		}
		/* range */
		if (strchr(a, '-')) {
			char *range[2];
			int low, high;

			strftok("-", a, range, 2);
			if (!strisnum(range[0]) || !strisnum(range[1]))
				goto err; /* syntax error */
			low = strtol(range[0], NULL, 0);
			high = strtol(range[1], NULL, 0);
			if (low > high) {
				int t;
				t = high;
				high = low;
				low = t;
			}
			for (i = low; i <= high; i++)
				pi[i].active = !neg;
		/* all the ports */
		} else if (!strcmp(a, "all")) {
			for (i = 0; i <= MAXPORT; i++)
				pi[i].active = !neg;
		/* /etc/services ports */
		} else if (!strcmp(a, "known")) {
			struct servent *se;
			setservent(0);
			while((se = getservent()) != NULL) {
				int port = ntohs(se->s_port);
				if (port < 0 || port > MAXPORT)
					continue;
				pi[port].active = !neg;
			}
		/* a single port */
		} else {
			int port;
			if (!strisnum(a))
				goto err; /* syntax error */
			port = strtol(a, NULL, 0);
			if (port < 0 || port > MAXPORT)
				goto err; /* syntax error */
			pi[port].active = !neg;
		}
	}
	free(p);
	return 0;
err:
	free(p);
	return 1;
}

/* -------------------------------- output ---------------------------------- */
static void sender(struct portinfo *pi)
{
	int i, retry = 0;
	time_t start_time;

	start_time = get_midnight_ut_ms();

	while(1) {
		int active = 0;
		int recvd = 0;
		retry ++;
		for (i = 0; i < MAXPORT; i++) {
			if (pi[i].active && pi[i].retry) {
				active++;
				pi[i].retry--;
				sequence = -1;
				dst_port = i;
				pi[i].sentms = get_midnight_ut_ms();
				send_tcp();
				if (opt_waitinusec) {
					if (usec_delay.it_interval.tv_usec)
						usleep(usec_delay.it_interval.tv_usec);
				} else {
					sleep(sending_wait);
				}
			}
		}
		avrgms = (float) pi[MAXPORT+1].active;
		if (retry >= 3) {
			if (opt_debug)
				printf("AVRGMS %f\n", avrgms);
			if (avrgms)
				usleep((int) (avrgms*1000));
			else
				sleep(1);
		}
		for (i = 0; i < MAXPORT; i++) {
			if (!pi[i].active && pi[i].retry)
				recvd++;
		}
		/* More to scan? */
		if (!active) {
			if (!recvd)
				sleep(1);
			fprintf(stderr, "All replies received. Done.\n");
			printf("Not responding ports: ");
			for (i = 0; i < MAXPORT; i++) {
				if (pi[i].active && !pi[i].retry)
					printf("(%d %.11s) ", i, port_to_name(i));
			}
			printf("\n");
			exit(0);
		}
		/* Are we sending too fast? */
		if ((!recvd && opt_waitinusec &&
		    usec_delay.it_interval.tv_usec == 0 &&
		    (get_midnight_ut_ms() - start_time) > 500) ||
			(opt_scan_probes-retry) <= 2)
		{
			if (opt_debug)
				printf("SLOWING DONW\n");
			usec_delay.it_interval.tv_usec *= 10;
			usec_delay.it_interval.tv_usec ++;
		}
	}
}

/* -------------------------------- input  ---------------------------------- */
static void receiver(struct portinfo *pi, int childpid)
{
	struct myiphdr ip;
	char packet[IP_MAX_SIZE+linkhdr_size];

	while(1)
	{
		int len, iplen;

		len = read_packet(packet, IP_MAX_SIZE+linkhdr_size);
		if (len == -1) {
			perror("read_packet");
			continue;
		}
		/* minimal sanity checks */
		if (len < linkhdr_size)
			continue;
		iplen = len - linkhdr_size;
		if (iplen < sizeof(struct myiphdr))
			continue;
		/* copy the ip header in an access-safe place */
		memcpy(&ip, packet+linkhdr_size, sizeof(ip));
		/* check if the dest IP matches */
		if (memcmp(&ip.daddr, &local.sin_addr, sizeof(ip.daddr)))
			continue;
		/* check if the source IP matches */
		if (ip.protocol != IPPROTO_ICMP &&
		    memcmp(&ip.saddr, &remote.sin_addr, sizeof(ip.saddr)))
			continue;
		if (ip.protocol == IPPROTO_TCP) {
			struct mytcphdr tcp;
			int iphdrlen = ip.ihl << 2;
			char flags[16];
			time_t rttms;
			int sport;

			/* more sanity checks */
			if ((iplen - iphdrlen) < sizeof(tcp))
				continue;
			/* time to copy the TCP header in a safe place */
			memcpy(&tcp, packet+linkhdr_size+iphdrlen, sizeof(tcp));

			/* check if the TCP dest port matches */
#if 0
			printf("SRC: %d DST: %d\n",
					ntohs(tcp.th_sport),
					ntohs(tcp.th_dport));
#endif
			if (ntohs(tcp.th_dport) != initsport)
				continue;
			sport = htons(tcp.th_sport);
			if (pi[sport].active == 0)
				continue;


			/* Note that we don't care about a wrote RTT
			 * result due to resend on the same port. */
			rttms = get_midnight_ut_ms() - pi[sport].sentms;

			avrgcount++;
			avrgms = (avrgms*(avrgcount-1)/avrgcount)+(rttms/avrgcount);
			/* The avrg RTT is shared using shared memory,
			 * no locking... */
			pi[MAXPORT+1].active = (int) avrgms;

			tcp_strflags(flags, tcp.th_flags);
#if 0
			printf("%5d: %s %3d %5d %5d %10ld (%2d)\n",
					sport,
					flags,
					ip.ttl,
					ip.id,
					ntohs(tcp.th_win),
					(long) rttms,
					opt_scan_probes-(pi[sport].retry));
#endif
			if ((tcp.th_flags & TH_SYN) || opt_verbose) {
			printf("%5d %-11.11s: %s %3d %5d %5d %5d\n",
					sport,
					port_to_name(sport),
					flags,
					ip.ttl,
					ip.id,
					ntohs(tcp.th_win),
					iplen);
			fflush(stdout);
			}
			pi[sport].active = 0;
		} else if (ip.protocol == IPPROTO_ICMP) {
			struct myicmphdr icmp;
			struct myiphdr subip;
			struct mytcphdr subtcp;
			int iphdrlen = ip.ihl << 2;
			unsigned char *p;
			int port;
			struct in_addr gwaddr;

			/* more sanity checks, we are only interested
			 * in ICMP quoting the original packet. */
			if ((iplen - iphdrlen) < sizeof(icmp)+sizeof(subip)+sizeof(subtcp))
				continue;
			/* time to copy headers in a safe place */
			p = packet+linkhdr_size+iphdrlen;
			memcpy(&icmp, p, sizeof(subtcp));
			p += sizeof(icmp);
			memcpy(&subip, p, sizeof(ip));
			p += sizeof(ip);
			memcpy(&subtcp, p, sizeof(subtcp));

			/* Check if the ICMP quoted packet matches */
			/* check if the source IP matches */
			if (memcmp(&subip.saddr, &local.sin_addr, sizeof(subip.saddr)))
				continue;
			/* check if the destination IP matches */
			if (memcmp(&subip.daddr, &remote.sin_addr, sizeof(subip.daddr)))
				continue;
			/* check if the quoted TCP packet port matches */
			if (ntohs(subtcp.th_sport) != initsport)
				continue;
			port = htons(subtcp.th_dport);
			if (pi[port].active == 0)
				continue;
			pi[port].active = 0;
			memcpy(&gwaddr.s_addr, &ip.saddr, 4);
			printf("%5d:                      %3d %5d %5d   (ICMP %3d %3d from %s)\n",
					port,
					ip.ttl,
					iplen,
					ntohs(ip.id),
					icmp.type,
					icmp.code,
					inet_ntoa(gwaddr));
		}
	}
}

/* ---------------------------------- main ---------------------------------- */
static void do_exit(int sid)
{
	exit(0);
}

void scanmain(void)
{
	struct portinfo *pi;
	int ports = 0, i;
	int childpid;

	pi = shm_init(sizeof(*pi)*(MAXPORT+2));
	pi[MAXPORT+1].active = 0; /* hold the average RTT */
	if (pi == NULL) {
		fprintf(stderr, "Unable to create the shared memory");
		shm_close(pi);
		exit(1);
	}
	for (i = 0; i <= MAXPORT; i++) {
		pi[i].active = 0;
		pi[i].retry = opt_scan_probes;
	}
	if (parse_ports(pi, opt_scanports)) {
		fprintf(stderr, "Ports syntax error for scan mode\n");
		shm_close(pi);
		exit(1);
	}
	for (i = 0; i <= MAXPORT; i++) {
		if (!pi[i].active)
			pi[i].retry = 0;
	}
	for (i = 0; i <= MAXPORT; i++)
		ports += pi[i].active;
	fprintf(stderr, "%d ports to scan, use -V to see all the replies\n", ports);
	fprintf(stderr, "+----+-----------+---------+---+-----+-----+-----+\n");
	fprintf(stderr, "|port| serv name |  flags  |ttl| id  | win | len |\n");
	fprintf(stderr, "+----+-----------+---------+---+-----+-----+-----+\n");

	/* We are ready to fork, the input and output parts
	 * are separated processes */
	if ((childpid = fork()) == -1) {
		perror("fork");
		shm_close(pi);
		exit(1);
	}
	/* The parent is the receiver, the child the sender.
	 * it's almost the same but this way is simpler
	 * to make it working in pipe with other commands like grep. */
	if (childpid) { /* parent */
		Signal(SIGCHLD, do_exit);
		Signal(SIGINT, do_exit);
		Signal(SIGTERM, do_exit);
		receiver(pi, childpid);
	} else {	/* child */
		Signal(SIGINT, do_exit);
		Signal(SIGTERM, do_exit);
		sender(pi);
	}
	/* UNREACHED */
}
