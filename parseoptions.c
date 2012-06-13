/* parseoptions.c -- options handling
 * Copyright(C) 1999-2001 Salvatore Sanfilippo
 * Under GPL, see the COPYING file for more information about
 * the license. */

/* $Id: parseoptions.c,v 1.2 2004/06/18 09:53:11 antirez Exp $ */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "antigetopt.h"

#include "hping2.h"
#include "globals.h"

enum {	OPT_COUNT, OPT_INTERVAL, OPT_NUMERIC, OPT_QUIET, OPT_INTERFACE,
	OPT_HELP, OPT_VERSION, OPT_DESTPORT, OPT_BASEPORT, OPT_TTL, OPT_ID,
	OPT_WIN, OPT_SPOOF, OPT_FIN, OPT_SYN, OPT_RST, OPT_PUSH, OPT_ACK,
	OPT_URG, OPT_XMAS, OPT_YMAS, OPT_FRAG, OPT_MOREFRAG, OPT_DONTFRAG,
	OPT_FRAGOFF, OPT_TCPOFF, OPT_REL, OPT_DATA, OPT_RAWIP, OPT_ICMP,
	OPT_UDP, OPT_BIND, OPT_UNBIND, OPT_DEBUG, OPT_VERBOSE, OPT_WINID,
	OPT_KEEP, OPT_FILE, OPT_DUMP, OPT_PRINT, OPT_SIGN, OPT_LISTEN,
	OPT_SAFE, OPT_TRACEROUTE, OPT_TOS, OPT_MTU, OPT_SEQNUM, OPT_BADCKSUM,
	OPT_SETSEQ, OPT_SETACK, OPT_ICMPTYPE, OPT_ICMPCODE, OPT_END,
	OPT_RROUTE, OPT_IPPROTO, OPT_ICMP_IPVER, OPT_ICMP_IPHLEN,
	OPT_ICMP_IPLEN, OPT_ICMP_IPID, OPT_ICMP_IPPROTO, OPT_ICMP_CKSUM,
	OPT_ICMP_TS, OPT_ICMP_ADDR, OPT_TCPEXITCODE, OPT_FAST, OPT_TR_KEEP_TTL,
	OPT_TCP_TIMESTAMP, OPT_TR_STOP, OPT_TR_NO_RTT, OPT_ICMP_HELP,
	OPT_RAND_DEST, OPT_RAND_SOURCE, OPT_LSRR, OPT_SSRR, OPT_ROUTE_HELP,
	OPT_ICMP_IPSRC, OPT_ICMP_IPDST, OPT_ICMP_SRCPORT, OPT_ICMP_DSTPORT,
	OPT_ICMP_GW, OPT_FORCE_ICMP, OPT_APD_SEND, OPT_SCAN, OPT_FASTER,
	OPT_BEEP, OPT_FLOOD, OPT_CLOCK_SKEW, OPT_CS_WINDOW, OPT_CS_WINDOW_SHIFT,
        OPT_CS_VECTOR_LEN };

static struct ago_optlist hping_optlist[] = {
	{ 'c',	"count",	OPT_COUNT,		AGO_NEEDARG },
	{ 'i',	"interval",	OPT_INTERVAL,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'n',	"numeric",	OPT_NUMERIC,		AGO_NOARG },
	{ 'q',	"quiet",	OPT_QUIET,		AGO_NOARG },
	{ 'I',	"interface",	OPT_INTERFACE,		AGO_NEEDARG },
	{ 'h',	"help",		OPT_HELP,		AGO_NOARG },
	{ 'v',	"version",	OPT_VERSION,		AGO_NOARG },
	{ 'p',	"destport",	OPT_DESTPORT,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 's',	"baseport",	OPT_BASEPORT,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 't',	"ttl",		OPT_TTL,		AGO_NEEDARG },
	{ 'N',	"id",		OPT_ID,			AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'w',	"win",		OPT_WIN,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'a',	"spoof",	OPT_SPOOF,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'F',	"fin",		OPT_FIN,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'S',	"syn",		OPT_SYN,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'R',	"rst",		OPT_RST,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'P',	"push",		OPT_PUSH,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'A',	"ack",		OPT_ACK,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'U',	"urg",		OPT_URG,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'X',	"xmas",		OPT_XMAS,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'Y',	"ymas",		OPT_YMAS,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'f',	"frag",		OPT_FRAG,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'x',	"morefrag",	OPT_MOREFRAG,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'y',	"dontfrag",	OPT_DONTFRAG,		AGO_NOARG },
	{ 'g',	"fragoff",	OPT_FRAGOFF,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'O',	"tcpoff",	OPT_TCPOFF,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'r',	"rel",		OPT_REL,		AGO_NOARG },
	{ 'd',	"data",		OPT_DATA,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '0',	"rawip",	OPT_RAWIP,		AGO_NOARG|AGO_EXCEPT0 },
	{ '1',	"icmp",		OPT_ICMP,		AGO_NOARG },
	{ '2',	"udp",		OPT_UDP,		AGO_NOARG },
	{ '8',	"scan",		OPT_SCAN,		AGO_NEEDARG },
	{ 'z',	"bind",		OPT_BIND,		AGO_NOARG },
	{ 'Z',	"unbind",	OPT_UNBIND,		AGO_NOARG },
	{ 'D',	"debug",	OPT_DEBUG,		AGO_NOARG },
	{ 'V',	"verbose",	OPT_VERBOSE,		AGO_NOARG },
	{ 'W',	"winid",	OPT_WINID,		AGO_NOARG },
	{ 'k',	"keep",		OPT_KEEP,		AGO_NOARG },
	{ 'E',	"file",		OPT_FILE,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'j',	"dump",		OPT_DUMP,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'J',	"print",	OPT_PRINT,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'e',	"sign",		OPT_SIGN,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '9',	"listen",	OPT_LISTEN,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'B',	"safe",		OPT_SAFE,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'T',	"traceroute",	OPT_TRACEROUTE,		AGO_NOARG },
	{ 'o',	"tos",		OPT_TOS,		AGO_NEEDARG },
	{ 'm',	"mtu",		OPT_MTU,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'Q',	"seqnum",	OPT_SEQNUM,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'b',	"badcksum",	OPT_BADCKSUM,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'M',	"setseq",	OPT_SETSEQ,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'L',	"setack",	OPT_SETACK,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'C',	"icmptype",	OPT_ICMPTYPE,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'K',	"icmpcode",	OPT_ICMPCODE,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ 'u',	"end",		OPT_END,		AGO_NOARG|AGO_EXCEPT0 },
	{ 'G',	"rroute",	OPT_RROUTE,		AGO_NOARG },
	{ 'H',	"ipproto",	OPT_IPPROTO,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-help",	OPT_ICMP_HELP,		AGO_NOARG },
	{ '\0',	"icmp-ipver",	OPT_ICMP_IPVER,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-iphlen",	OPT_ICMP_IPHLEN, 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-iplen",	OPT_ICMP_IPLEN,	 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-ipid",	OPT_ICMP_IPID,	 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-ipproto",	OPT_ICMP_IPPROTO, 	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-cksum",	OPT_ICMP_CKSUM,   	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0',	"icmp-ts",	OPT_ICMP_TS,		AGO_NOARG },
	{ '\0', "icmp-addr",	OPT_ICMP_ADDR,		AGO_NOARG },
	{ '\0', "tcpexitcode",	OPT_TCPEXITCODE,	AGO_NOARG },
	{ '\0',	"fast",		OPT_FAST,		AGO_NOARG|AGO_EXCEPT0 },
	{ '\0',	"faster",	OPT_FASTER,		AGO_NOARG|AGO_EXCEPT0 },
	{ '\0',	"tr-keep-ttl",	OPT_TR_KEEP_TTL,	AGO_NOARG },
	{ '\0', "tcp-timestamp",OPT_TCP_TIMESTAMP,	AGO_NOARG },
	{ '\0', "tr-stop",	OPT_TR_STOP,		AGO_NOARG },
	{ '\0',	"tr-no-rtt",	OPT_TR_NO_RTT,		AGO_NOARG },
	{ '\0', "rand-dest",	OPT_RAND_DEST,		AGO_NOARG },
	{ '\0', "rand-source",	OPT_RAND_SOURCE,	AGO_NOARG },
	{ '\0', "lsrr",		OPT_LSRR, 		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "ssrr",		OPT_SSRR, 		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "route-help",   OPT_ROUTE_HELP,		AGO_NOARG },
	{ '\0', "apd-send",	OPT_APD_SEND,		AGO_NEEDARG },
	{ '\0', "icmp-ipsrc",	OPT_ICMP_IPSRC,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-ipdst",	OPT_ICMP_IPDST,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-gw",	OPT_ICMP_GW,		AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-srcport", OPT_ICMP_SRCPORT,	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "icmp-dstport", OPT_ICMP_DSTPORT,	AGO_NEEDARG|AGO_EXCEPT0 },
	{ '\0', "force-icmp",	OPT_FORCE_ICMP,		AGO_NOARG },
	{ '\0', "beep",		OPT_BEEP,		AGO_NOARG },
	{ '\0', "flood",	OPT_FLOOD,		AGO_NOARG },
	{ '\0', "clock-skew",	OPT_CLOCK_SKEW,		AGO_NOARG },
	{ '\0', "clock-skew-win", OPT_CS_WINDOW,	AGO_NEEDARG},
	{ '\0', "clock-skew-win-shift", OPT_CS_WINDOW_SHIFT,	AGO_NEEDARG},
	{ '\0', "clock-skew-packets-per-sample", OPT_CS_VECTOR_LEN,AGO_NEEDARG},
	AGO_LIST_TERM
};

/* The following var is turned to 1 if the -i option is used.
 * This allows to assign a different delay default value if
 * the scanning mode is selected. */
static int delay_changed = 0;

static int suidtester(void)
{
	return (getuid() != geteuid());
}

void fail_parse_route(void)
{
    fprintf(stderr, "RECTUM\n");
    exit(1);
}

void parse_route(unsigned char *route, unsigned int *route_len, char *str)
{
    struct in_addr ip;
    unsigned int i = 0;
    unsigned int j;
    unsigned int n = 0;
    unsigned int route_ptr = 256;
    char c;

    route += 3;
    while (str[i] != '\0')
    {
        for (j = i; isalnum(str[j]) || str[j] == '.'; j++);
        switch(c = str[j])
        {
            case '\0':
            case '/':
                if (n >= 62)
                {
                    fprintf(stderr, "too long route\n");
                    fail_parse_route();
                }
                str[j] = '\0';
                if (inet_aton(str+i, &ip))
                {
                    memcpy(route+4*n, &ip.s_addr, 4);
                    n++;
                    if (c == '/')
                        str[j++] = '/';
                    break;
                }
                fprintf(stderr, "invalid IP adress in route\n");
                fail_parse_route();
            case ':':
                if ((!i) && j && j < 4)
                {
                    sscanf(str, "%u:%n", &route_ptr, &i);
                    if (i == ++j)
                    {
                        if (route_ptr < 256)
                            break;
                    }
                }
            default:
                fail_parse_route();
        }
        i = j;
    }
    if (route_ptr == 256)
        route[-1] = (unsigned char) ( n ? 8 : 4 );
    else
        route[-1] = (unsigned char) route_ptr;
    *route_len = 4*n + 3;
    route[-2] = (unsigned char) *route_len;
}

int parse_options(int argc, char **argv)
{
	int src_ttl_set = 0;
	int targethost_set = 0;
	int o;

	if (argc < 2)
		return -1;

	ago_set_exception(0, suidtester, "Option disabled when setuid");

	while ((o = antigetopt(argc, argv, hping_optlist)) != AGO_EOF) {
		switch(o) {
		case AGO_UNKNOWN:
		case AGO_REQARG:
		case AGO_AMBIG:
			ago_gnu_error("hping", o);
			fprintf(stderr, "Try hping --help\n");
			exit(1);
		case AGO_ALONE:
			if (targethost_set == 1) {
				fprintf(stderr, "hping: you must specify only "
						"one target host at a time\n");
				exit(1);
			} else {
				strlcpy(targetname, ago_optarg, 1024);
				targethost_set = 1;
			}
			break;
		case OPT_COUNT:
			count = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_INTERVAL:
			delay_changed = 1;
			if (*ago_optarg == 'u') {
				opt_waitinusec = TRUE;
				usec_delay.it_value.tv_sec =
				usec_delay.it_interval.tv_sec = 0;
				usec_delay.it_value.tv_usec = 
				usec_delay.it_interval.tv_usec =
					atol(ago_optarg+1);
			}
			else
				sending_wait = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_NUMERIC:
			opt_numeric = TRUE;
			break;
		case OPT_QUIET:
			opt_quiet = TRUE;
			break;
		case OPT_INTERFACE:
			strlcpy (ifname, ago_optarg, 1024);
			break;
		case OPT_HELP:
			show_usage();
			break;
		case OPT_VERSION:
			show_version();
			break;
		case OPT_DESTPORT:
			if (*ago_optarg == '+')
			{
				opt_incdport = TRUE;
				ago_optarg++;
			}
			if (*ago_optarg == '+')
			{
				opt_force_incdport = TRUE;
				ago_optarg++;
			}
			base_dst_port = dst_port = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_BASEPORT:
			initsport = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_TTL:
			src_ttl = strtol(ago_optarg, NULL, 0);
			src_ttl_set = 1;
			break;
		case OPT_ID:
			src_id = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_WIN:
			src_winsize = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_SPOOF:
			strlcpy (spoofaddr, ago_optarg, 1024);
			break;
		case OPT_FIN:
			tcp_th_flags |= TH_FIN;
			break;
		case OPT_SYN:
			tcp_th_flags |= TH_SYN;
			break;
		case OPT_RST:
			tcp_th_flags |= TH_RST;
			break;
		case OPT_PUSH:
			tcp_th_flags |= TH_PUSH;
			break;
		case OPT_ACK:
			tcp_th_flags |= TH_ACK;
			break;
		case OPT_URG:
			tcp_th_flags |= TH_URG;
			break;
		case OPT_XMAS:
			tcp_th_flags |= TH_X;
			break;
		case OPT_YMAS:
			tcp_th_flags |= TH_Y;
			break;
		case OPT_FRAG:
			opt_fragment = TRUE;
			break;
		case OPT_MOREFRAG:
			opt_mf = TRUE;
			break;
		case OPT_DONTFRAG:
			opt_df = TRUE;
			break;
		case OPT_FRAGOFF:
			ip_frag_offset = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_TCPOFF:
			src_thoff = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_REL:
			opt_relid = TRUE;
			break;
		case OPT_DATA:
			data_size = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_RAWIP:
			opt_rawipmode = TRUE;
			break;
		case OPT_ICMP:
			opt_icmpmode = TRUE;
			break;
		case OPT_ICMP_TS:
			opt_icmpmode = TRUE;
			opt_icmptype = 13;
			break;
		case OPT_ICMP_ADDR:
			opt_icmpmode = TRUE;
			opt_icmptype = 17;
			break;
		case OPT_UDP:
			opt_udpmode = TRUE;
			break;
		case OPT_SCAN:
			opt_scanmode = TRUE;
			opt_scanports = strdup(ago_optarg);
			break;
		case OPT_LISTEN:
			opt_listenmode = TRUE;
			strlcpy(sign, ago_optarg, 1024);
			signlen = strlen(ago_optarg);
			break;
		case OPT_IPPROTO:
			raw_ip_protocol = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMPTYPE:
			opt_icmpmode= TRUE;
			opt_icmptype = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMPCODE:
			opt_icmpmode= TRUE;
			opt_icmpcode = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_BIND:
			ctrlzbind = BIND_TTL;
			break;
		case OPT_UNBIND:
			ctrlzbind = BIND_NONE;
			break;
		case OPT_DEBUG:
			opt_debug = TRUE;
			break;
		case OPT_VERBOSE:
			opt_verbose = TRUE;
			break;
		case OPT_WINID:
			opt_winid_order = TRUE;
			break;
		case OPT_KEEP:
			opt_keepstill = TRUE;
			break;
		case OPT_FILE:
			opt_datafromfile = TRUE;
			strlcpy(datafilename, ago_optarg, 1024);
			break;
		case OPT_DUMP:
			opt_hexdump = TRUE;
			break;
		case OPT_PRINT:
			opt_contdump = TRUE;
			break;
		case OPT_SIGN:
			opt_sign = TRUE;
			strlcpy(sign, ago_optarg, 1024);
			signlen = strlen(ago_optarg);
			break;
		case OPT_SAFE:
			opt_safe = TRUE;
			break;
		case OPT_END:
			opt_end = TRUE;
			break;
		case OPT_TRACEROUTE:
			opt_traceroute = TRUE;
			break;
		case OPT_TOS:
			if (!strcmp(ago_optarg, "help"))
				tos_help();
			else
			{
				static unsigned int tos_tmp = 0;

				sscanf(ago_optarg, "%2x", &tos_tmp);
				ip_tos |= tos_tmp; /* OR tos */
			}
			break;
		case OPT_MTU:
			virtual_mtu = strtol(ago_optarg, NULL, 0);
			opt_fragment = TRUE;
			if(virtual_mtu > 65535) {
				virtual_mtu = 65535;
				printf("Specified MTU too high, "
					"fixed to 65535.\n");
			}
			break;
		case OPT_SEQNUM:
			opt_seqnum = TRUE;
			break;
		case OPT_BADCKSUM:
			opt_badcksum = TRUE;
			break;
		case OPT_SETSEQ:
			set_seqnum = TRUE;
			tcp_seqnum = strtoul(ago_optarg, NULL, 0);
			break;
		case OPT_SETACK:
			set_ack = TRUE;
			tcp_ack = strtoul(ago_optarg, NULL, 0);
			break;
		case OPT_RROUTE:
			opt_rroute = TRUE;
			break;
		case OPT_ICMP_HELP:
			icmp_help();	/* ICMP options help */
			break;
		case OPT_ICMP_IPVER:
			icmp_ip_version = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMP_IPHLEN:
			icmp_ip_ihl = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMP_IPLEN:
			icmp_ip_tot_len = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMP_IPID:
			icmp_ip_id = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMP_IPPROTO:
			icmp_ip_protocol = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMP_IPSRC:
			strlcpy (icmp_ip_srcip, ago_optarg, 1024);
			break;
		case OPT_ICMP_IPDST:
			strlcpy (icmp_ip_dstip, ago_optarg, 1024);
			break;
		case OPT_ICMP_GW:
			strlcpy (icmp_gwip, ago_optarg, 1024);
			break;
		case OPT_ICMP_SRCPORT:
			icmp_ip_srcport = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_ICMP_DSTPORT:
			icmp_ip_dstport = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_FORCE_ICMP:
			opt_force_icmp = TRUE;
			break;
		case OPT_ICMP_CKSUM:
			icmp_cksum = strtol(ago_optarg, NULL, 0);
			break;
		case OPT_TCPEXITCODE:
			opt_tcpexitcode = TRUE;
			break;
		case OPT_FAST:
			delay_changed = 1;
			opt_waitinusec = TRUE;
			usec_delay.it_value.tv_sec =
			usec_delay.it_interval.tv_sec = 0;
			usec_delay.it_value.tv_usec = 
			usec_delay.it_interval.tv_usec = 100000;
			break;
		case OPT_FASTER:
			delay_changed = 1;
			opt_waitinusec = TRUE;
			usec_delay.it_value.tv_sec =
			usec_delay.it_interval.tv_sec = 0;
			usec_delay.it_value.tv_usec = 
			usec_delay.it_interval.tv_usec = 1;
		case OPT_TR_KEEP_TTL:
			opt_tr_keep_ttl = TRUE;
			break;
		case OPT_TCP_TIMESTAMP:
			opt_tcp_timestamp = TRUE;
			break;
		case OPT_TR_STOP:
			opt_tr_stop = TRUE;
			break;
		case OPT_TR_NO_RTT:
			opt_tr_no_rtt = TRUE;
			break;
		case OPT_RAND_DEST:
			opt_rand_dest = TRUE;
			break;
		case OPT_RAND_SOURCE:
			opt_rand_source = TRUE;
			break;
		case OPT_LSRR:
			opt_lsrr = TRUE;
			parse_route(lsr, &lsr_length, ago_optarg);
			if (lsr[0])
				printf("Warning: erasing previously given "
						"loose source route");
			lsr[0] = 131;
			break;
		case OPT_SSRR:
			opt_ssrr = TRUE;
			parse_route(ssr, &ssr_length, ago_optarg);
			if (ssr[0])
				printf("Warning: erasing previously given "
						"strong source route");
			ssr[0] = 137;
			break;
		case OPT_ROUTE_HELP:
			route_help();
			break;
		case OPT_APD_SEND:
			hping_ars_send(ago_optarg);
			break;
		case OPT_BEEP:
			opt_beep = TRUE;
			break;
		case OPT_FLOOD:
			opt_flood = TRUE;
			break;
                case OPT_CLOCK_SKEW:
			opt_tcp_timestamp = TRUE;
                        opt_clock_skew = TRUE;
                        break;
                case OPT_CS_WINDOW:
                        cs_window = strtol(ago_optarg, NULL, 0);
                        if (cs_window < 30) {
                            fprintf(stderr,
                                    "clock skew window can't be < 30 sec.\n");
                            exit(1);
                        }
                        break;
                case OPT_CS_WINDOW_SHIFT:
                        cs_window_shift = strtol(ago_optarg, NULL, 0);
                        if (cs_window_shift < 1) {
                            fprintf(stderr,
                                    "clock skew window shift can't be < 1\n");
                            exit(1);
                        }
                        break;
                case OPT_CS_VECTOR_LEN:
                        cs_vector_len = strtol(ago_optarg, NULL, 0);
                        if (cs_vector_len < 1) {
                            fprintf(stderr,
                                    "clock skew packets per sample can't be < 1\n");
                            exit(1);
                        }
                        break;
		}
	}

	/* missing target host? */
	if (targethost_set == 0 && opt_listenmode && opt_safe)
	{
		printf(
		"you must specify a target host if you require safe protocol\n"
		"because hping needs a target for HCMP packets\n");
		exit(1);
	}

	if (targethost_set == 0 && !opt_listenmode) return -1;

	if (opt_numeric == TRUE) opt_gethost = FALSE;

	/* some error condition */
	if (data_size+IPHDR_SIZE+TCPHDR_SIZE > 65535) {
		printf("Option error: sorry, data size must be <= %lu\n",
			(unsigned long)(65535-IPHDR_SIZE+TCPHDR_SIZE));
		exit(1);
	}
	else if (count <= 0 && count != -1) {
		printf("Option error: count must > 0\n");
		exit(1);
	}
	else if (sending_wait < 0) {
		printf("Option error: bad timing interval\n");
		exit(1);
	}
	else if (opt_waitinusec == TRUE && usec_delay.it_value.tv_usec < 0)
	{
		printf("Option error: bad timing interval\n");
		exit(1);
	}
	else if (opt_datafromfile == TRUE && data_size == 0)
	{
		printf("Option error: -E option useless without -d\n");
		exit(1);
	}
	else if (opt_sign && data_size && signlen > data_size)
	{
		printf(
	"Option error: signature (%d bytes) is larger than data size\n"
	"check -d option, don't specify -d to let hping compute it\n", signlen);
		exit(1);
	}
	else if ((opt_sign || opt_listenmode) && signlen > 1024)
	{
		printf("Option error: signature too big\n");
		exit(1);
	}
	else if (opt_safe == TRUE && src_id != -1)
	{
		printf("Option error: sorry, you can't set id and "
				"use safe protocol at some time\n");
		exit(1);
	}
	else if (opt_safe == TRUE && opt_datafromfile == FALSE &&
			opt_listenmode == FALSE)
	{
		printf("Option error: sorry, safe protocol is useless "
				"without 'data from file' option\n");
		exit(1);
	}
	else if (opt_safe == TRUE && opt_sign == FALSE &&
			opt_listenmode == FALSE)
	{
		printf("Option error: sorry, safe protocol require you "
				"sign your packets, see --sign | -e option\n");
		exit(1);
	} else if (opt_rand_dest == TRUE && ifname[0] == '\0') {
		printf("Option error: you need to specify an interface "
			"when the --rand-dest option is enabled\n");
		exit(1);
	}

	/* dependences */
	if (opt_safe == TRUE)
		src_id = 1;

	if (opt_traceroute == TRUE && ctrlzbind == BIND_DPORT)
		ctrlzbind = BIND_TTL;

	if (opt_traceroute == TRUE && src_ttl_set == 0)
		src_ttl = DEFAULT_TRACEROUTE_TTL;

	/* set the data size to the signature len if the no data size
	 * was specified */
	if (opt_sign && !data_size)
		data_size = signlen;

	/* If scan mode is on, and the -i option was not used,
	 * set the default delay to zero, that's send packets
	 * as fast as possible. */
	if (opt_scanmode && !delay_changed) {
		opt_waitinusec = TRUE;
		usec_delay.it_value.tv_sec =
		usec_delay.it_interval.tv_sec = 0;
		usec_delay.it_value.tv_usec = 
		usec_delay.it_interval.tv_usec = 0;
	}

	return 1;
}
