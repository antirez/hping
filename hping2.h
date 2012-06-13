/* 
 * $smu-mark$ 
 * $name: hping2.h$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:48 MET 1999$ 
 * $rev: 9$ 
 */ 

/* $Id: hping2.h,v 1.4 2004/06/04 07:22:38 antirez Exp $ */

#ifndef _HPING2_H
#define _HPING2_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <limits.h>
#include "byteorder.h"
#include "systype.h"
#include "fixtypes.h"

/* types */
#ifndef __u8
#define __u8		u_int8_t
#endif /* __u8 */
#ifndef __u16
#define __u16		u_int16_t
#endif /* __u16 */
#ifndef __u32
#define __u32		u_int32_t
#endif /* __u32 */

#ifndef __uint8_t
#define __uint8_t	u_int8_t
#endif /* __uint8_t */
#ifndef __uint16_t
#define __uint16_t	u_int16_t
#endif /* __uint16_t */
#ifndef __uint32_t
#define __uint32_t	u_int32_t
#endif /* __uint32_t */

#include "hcmp.h" /* Hping Control Message Protocol */

/* protocols header size */
#ifndef ICMPHDR_SIZE
#define ICMPHDR_SIZE	sizeof(struct myicmphdr)
#endif
#ifndef UDPHDR_SIZE
#define UDPHDR_SIZE	sizeof(struct myudphdr)
#endif
#ifndef TCPHDR_SIZE
#define TCPHDR_SIZE	sizeof(struct mytcphdr)
#endif
#ifndef IPHDR_SIZE
#define IPHDR_SIZE	sizeof(struct myiphdr)
#endif

/* wait X seconds after reached to sent packets in oreder to display replies */
#define COUNTREACHED_TIMEOUT 1

/* requests status table stuffs */
/* Warning, TABLESIZE 0 == floating point exception */
#define TABLESIZE	400
#define S_SENT		0
#define S_RECV		1

/* usefull defines */
#ifndef TRUE
#define TRUE	1
#define FALSE	0
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
#ifndef PF_PACKET
#define PF_PACKET 17		/* kernel 2.[12].* with 2.0.* kernel headers? */
#endif
#ifndef ETH_P_IP
#define ETH_P_IP  0x0800	/* Internet Protocol packet     */
#endif
#ifndef ABS
#define ABS(x) (((x)>0) ? (x) : -(x))
#endif

/* header size of some physical layer type */
#define PPPHDR_SIZE_LINUX	0
#define PPPHDR_SIZE_FREEBSD	4
#define PPPHDR_SIZE_OPENBSD	4
#define PPPHDR_SIZE_NETBSD	4
#define PPPHDR_SIZE_BSDI	4
#define ETHHDR_SIZE		14
#define LOHDR_SIZE		14
#define WLANHDR_SIZE		14
#define TRHDR_SIZE		20

/* packet size (physical header size + ip header + tcp header + 0 data bytes) */
#ifndef IP_MAX_SIZE
#define IP_MAX_SIZE	65535
#endif 

/* absolute offsets */
#define ABS_OFFSETIP	linkhdr_size
#define ABS_OFFSETTCP	( linkhdr_size + IPHDR_SIZE )
#define ABS_OFFSETICMP	( linkhdr_size + IPHDR_SIZE )
#define ABS_OFFSETUDP	( linkhdr_size + IPHDR_SIZE )

/* defaults and misc */
#define DEFAULT_SENDINGWAIT 1	/* wait 1 sec. between sending each packets */
#define DEFAULT_DPORT	    0	/* default dest. port */
#define DEFAULT_INITSPORT  -1	/* default initial source port: -1 means random */
#define DEFAULT_COUNT      -1	/* default packets count: -1 means forever */
#define DEFAULT_TTL	   64	/* default ip->ttl value */
#define DEFAULT_SRCWINSIZE 512	/* default tcp windows size */
#define DEFAULT_VIRTUAL_MTU 16  /* tiny fragments */
#define DEFAULT_ICMP_TYPE   8	/* echo request */
#define DEFAULT_ICMP_CODE   0	/* icmp-type relative */
#define DEFAULT_ICMP_IP_VERSION		4
#define DEFAULT_ICMP_IP_IHL		(IPHDR_SIZE >> 2)
#define	DEFAULT_ICMP_IP_TOS		0
#define DEFAULT_ICMP_IP_TOT_LEN		0 /* computed by send_icmp_*() */
#define DEFAULT_ICMP_IP_ID		0 /* rand */
#define DEFAULT_ICMP_CKSUM		-1 /* -1 means compute the cksum */
#define DEFAULT_ICMP_IP_PROTOCOL	6 /* TCP */
#define DEFAULT_RAW_IP_PROTOCOL		6 /* TCP */
#define DEFAULT_TRACEROUTE_TTL		1

#define BIND_NONE	0		/* no bind */
#define BIND_DPORT	1		/* bind destination port */
#define BIND_TTL	2		/* bind ip->ttl */
#define DEFAULT_BIND	BIND_DPORT

#define DEFAULT_CS_WINDOW   300
#define DEFAULT_CS_WINDOW_SHIFT 5
#define DEFAULT_CS_VECTOR_LEN   10
	
/* fragmentation defines */
#define MF ((unsigned short)0x2000)	/* more fragments */
#define DF ((unsigned short)0x4000)	/* dont fragment */
#define NF ((unsigned short)0x0000)	/* no more fragments */

/* ip options defines */
#define IPOPT_COPY		0x80
#define IPOPT_CLASS_MASK	0x60
#define IPOPT_NUMBER_MASK	0x1f

#define	IPOPT_COPIED(o)		((o)&IPOPT_COPY)
#define	IPOPT_CLASS(o)		((o)&IPOPT_CLASS_MASK)
#define	IPOPT_NUMBER(o)		((o)&IPOPT_NUMBER_MASK)

#define	IPOPT_CONTROL		0x00
#define	IPOPT_RESERVED1		0x20
#define	IPOPT_MEASUREMENT	0x40
#define	IPOPT_RESERVED2		0x60

#define IPOPT_END	(0 |IPOPT_CONTROL)
#define IPOPT_NOOP	(1 |IPOPT_CONTROL)
#define IPOPT_SEC	(2 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_LSRR	(3 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_TIMESTAMP	(4 |IPOPT_MEASUREMENT)
#define IPOPT_RR	(7 |IPOPT_CONTROL)
#define IPOPT_SID	(8 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_SSRR	(9 |IPOPT_CONTROL|IPOPT_COPY)
#define IPOPT_RA	(20|IPOPT_CONTROL|IPOPT_COPY)

#define IPOPT_OPTVAL 0
#define IPOPT_OLEN   1
#define IPOPT_OFFSET 2
#define IPOPT_MINOFF 4
#define MAX_IPOPTLEN 40
#define IPOPT_NOP IPOPT_NOOP
#define IPOPT_EOL IPOPT_END
#define IPOPT_TS  IPOPT_TIMESTAMP

#define	IPOPT_TS_TSONLY		0		/* timestamps only */
#define	IPOPT_TS_TSANDADDR	1		/* timestamps and addresses */
#define	IPOPT_TS_PRESPEC	3		/* specified modules only */

/* tcp flags */
#ifndef	TH_FIN
#define TH_FIN  0x01
#endif
#ifndef TH_SYN
#define TH_SYN  0x02
#endif
#ifndef TH_RST
#define TH_RST  0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK  0x10
#endif
#ifndef TH_URG
#define TH_URG  0x20
#endif
#ifndef TH_X
#define	TH_X 0x40	/* X tcp flag */
#endif
#ifndef TH_Y
#define TH_Y 0x80	/* Y tcp flag */
#endif

/* ICMP TYPE */
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */

/* Codes for UNREACHABLE */
#define ICMP_NET_UNREACH        0       /* Network Unreachable          */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable             */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable         */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable             */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set  */
#define ICMP_SR_FAILED          5       /* Source Route failed          */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */
#define NR_ICMP_UNREACH 15        /* instead of hardcoding immediate value */

/* Codes for REDIRECT */
#define ICMP_REDIR_NET          0       /* Redirect Net                 */
#define ICMP_REDIR_HOST         1       /* Redirect Host                */
#define ICMP_REDIR_NETTOS       2       /* Redirect Net for TOS         */
#define ICMP_REDIR_HOSTTOS      3       /* Redirect Host for TOS        */

/* Codes for TIME_EXCEEDED */
#define ICMP_EXC_TTL            0       /* TTL count exceeded           */
#define ICMP_EXC_FRAGTIME       1       /* Fragment Reass time exceeded */

/*
 * IP header
 */
struct myiphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __u8    ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
        __u8    version:4,
                ihl:4;
#else
#error  "Please, edit Makefile and add -D__(LITTLE|BIG)_ENDIAN_BITFIEND"
#endif
        __u8    tos;
        __u16   tot_len;
        __u16   id;
        __u16   frag_off;
        __u8    ttl;
        __u8    protocol;
        __u16   check;
        __u32   saddr;
        __u32   daddr;
};

/*
 * UDP header
 */
struct myudphdr { 
	__u16 uh_sport;     /* source port */
	__u16 uh_dport;     /* destination port */
	__u16 uh_ulen;      /* udp length */
	__u16 uh_sum;       /* udp checksum */
};

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct mytcphdr {
	__u16	th_sport;               /* source port */
	__u16	th_dport;               /* destination port */
	__u32	th_seq;                 /* sequence number */
	__u32	th_ack;                 /* acknowledgement number */
#if defined (__LITTLE_ENDIAN_BITFIELD)
	__u8    th_x2:4,                /* (unused) */
		th_off:4;               /* data offset */
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8    th_off:4,               /* data offset */
		th_x2:4;                /* (unused) */
#else
#error  "Please, edit Makefile and add -D__(LITTLE|BIG)_ENDIAN_BITFIEND"
#endif
	__u8    th_flags;
	__u16   th_win;                 /* window */
	__u16   th_sum;                 /* checksum */
	__u16   th_urp;                 /* urgent pointer */
};

/*
 * ICMP header
 */
struct myicmphdr
{
	__u8          type;
	__u8          code;
	__u16         checksum;
	union
	{
		struct
		{
			__u16   id;
			__u16   sequence;
		} echo;
		__u32   gateway;
	} un;
};

struct icmp_tstamp_data {
	__u32 orig;
	__u32 recv;
	__u32 tran;
};

/*
 * UDP/TCP pseudo header
 * for cksum computing
 */
struct pseudohdr
{
	__u32 saddr;
	__u32 daddr;
	__u8  zero;
	__u8  protocol;
	__u16 lenght;
};

#define PSEUDOHDR_SIZE sizeof(struct pseudohdr)

/*
 * hping replies delay table
 */
struct delaytable_element {
	int seq;
	int src;
	time_t sec;
	time_t usec;
	int status;
};

volatile struct delaytable_element delaytable[TABLESIZE];

/* protos */
void	nop(void);				/* nop */
int	parse_options(int, char**);		/* option parser */
int	get_if_name(void);			/* get interface (see source) */
int	get_output_if(struct sockaddr_in *dest, struct sockaddr_in *ifip);
int	dltype_to_lhs(int dltype);
int	get_linkhdr_size(char*);		/* get link layer hdr size */
int	open_sockpacket(void);			/* open SOCK_PACKET socket */
int	open_sockpacket_ifindex(int ifindex);
int	close_sockpacket(int);			/* close SOCK_PACKET socket */
int	open_sockraw(void);			/* open raw socket */
void	send_packet (int signal_id);
void	send_rawip (void);
void	send_tcp(void);
void	send_udp(void);
void	send_icmp(void);
void	send_hcmp(__u8 type, __u32 arg);	/* send hcmp packets */
void	send_ip (char*, char*, char*, unsigned int, int, unsigned short,
		 char*, char);
void	send_ip_handler(char *packet, unsigned int size); /* fragmentation
                                                             handler */
void	wait_packet(void);			/* handle incoming packets */
void	print_statistics(int);
void	show_usage(void);
void	show_version(void);
int	resolve_addr(struct sockaddr * addr, char *hostname); /* resolver */
void	resolve(struct sockaddr*, char*);	/* resolver, exit on err. */
void	log_icmp_unreach(char*, unsigned short);/* ICMP unreachable logger */
void	log_icmp_timeexc(char*, unsigned short);/* ICMP time exceeded logger */
time_t	get_usec(void);				/* return current usec */
time_t	milliseconds(void);			/* ms from UT midnight */
long long mstime(void);                         /* ms from 1 Jan 1970 */
#define get_midnight_ut_ms milliseconds		/* backward compatibilty */
__u16	cksum(__u16 *buf, int nwords);		/* compute 16bit checksum */
void	inc_destparm(int sid);			/* inc dst port or ttl */
char	*get_hostname(char*);			/* get host from addr */
void	datafiller(char *p, int size);		/* fill data from file */
void	data_handler(char *data, int data_size);/* handle data filling */
void	socket_broadcast(int sd);		/* set SO_BROADCAST option */
void	socket_iphdrincl(int sd);		/* set SO_IPHDRINCL option */
void	listenmain(void);			/* main for listen mode */
char	*memstr(char *haystack, char *needle, int size); /* memstr */
void	tos_help(void);				/* show the TOS help */
int	rtt(int *seqp, int recvport, float *ms_delay);	/* compute round trip time */
int	relativize_id(int seqnum, int *ip_id);	/* compute relative id */
int	if_promisc_on(int s);			/* promisc. mode ON */
int	if_promisc_off(int s);			/* promisc. mode OFF */
int	open_pcap(void);			/* open libpcap socket */
int	close_pcap(void);			/* close libpcap socket */
int	pcap_recv(char *, unsigned int);	/* libpcap api wrapper */
int	memlock(char *addr, size_t size);	/* disable paging */
int	memunlock(char *addr, size_t size);	/* enable paging */
int	memlockall(void);			/* disable paging (all pages) */
int	memunlockall(void);			/* enable paging (all pages) */
unsigned char ip_opt_build(char *ip_opt);		/* build ip options */
void	display_ipopt(char* buf);		/* display ip options */
void	icmp_help(void);			/* show the ICMP help */
void	route_help(void);			/* show the route help */
void	(*Signal(int signo, void (*func)(int)))(int);
void	delaytable_add(int seq, int src, time_t sec, time_t usec, int status);
int	read_packet(void *packet, int size);
void	scanmain(void);
void	hping_script(int argc, char **argv);
u_int32_t hp_rand(void);
#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && \
    !defined(__bsdi__) && !defined(__APPLE__)
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif

/* ARS glue */
void hping_ars_send(char *s);

#endif /* _HPING2_H */
