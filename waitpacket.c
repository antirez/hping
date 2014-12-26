/* waitpacket.c -- handle and print the incoming packet
 * Copyright(C) 1999-2001 Salvatore Sanfilippo
 * Under GPL, see the COPYING file for more information about
 * the license. */

/* $Id: waitpacket.c,v 1.4 2004/06/18 09:53:11 antirez Exp $ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>

#include "hping2.h"
#include "globals.h"

static int icmp_unreach_rtt(void *quoted_ip, int size,
			    int *seqp, float *ms_delay);
static void print_tcp_timestamp(void *tcp, int tcpsize, int rttms);
static int recv_icmp(void *packet, size_t size);
static int recv_udp(void *packet, size_t size);
static int recv_tcp(void *packet, size_t size);
static void hex_dump(void *packet, int size);
static void human_dump(void *packet, int size);
static void handle_hcmp(char *packet, int size);

static struct myiphdr ip;
static int ip_size;
static struct in_addr src, dst;

/* This function is called for every matching packet received.
 * If --beep option was specified, the user will hear a beep
 * for every received packet. */
void recv_beep(void)
{
	if (opt_beep)
		printf("\a");
}

void wait_packet(void)
{
	int match = 0;
	int size, iphdr_size, enc_size;
	char packet [IP_MAX_SIZE+linkhdr_size];
	char *ip_packet, *enc_packet;

	size = read_packet(packet, IP_MAX_SIZE+linkhdr_size);
	switch(size) {
	case 0:
		return;
	case -1:
		exit(1);
	}

	/* Check if the packet is shorter than the link header size */
	if (size < linkhdr_size) {
		if (opt_debug)
			printf("DEBUG: WARNING: packet size < linkhdr_size\n");
		return;
	}

	/* IP packet pointer and len */
	ip_packet = packet + linkhdr_size;
	ip_size = size - linkhdr_size;

	/* Truncated IP header? */
	if (ip_size < IPHDR_SIZE) {
		if (opt_debug)
			printf("[|ip fix]\n");
		return;
	}

	memcpy(&ip, packet+linkhdr_size, sizeof(ip));
	iphdr_size = ip.ihl * 4;

	/* Bad IP header len? */
	if (iphdr_size > ip_size) {
		if (opt_debug)
			printf("[|iphdr size]\n");
		return;
	}

	/* Handle the HCMP for almost safe file transfer with hping */
	if (opt_sign)
		handle_hcmp(ip_packet, ip_size);

	/* Check if the dest IP address is the one of our interface */
	if (memcmp(&ip.daddr, &local.sin_addr, sizeof(ip.daddr)))
		return;
	/* If the packet isn't an ICMP error it should come from
	 * our target IP addresss. We accepts packets from all the
	 * source if the random destination option is active */
	if (ip.protocol != IPPROTO_ICMP && !opt_rand_dest) {
		if (memcmp(&ip.saddr, &remote.sin_addr, sizeof(ip.saddr)))
			return;
	}

	/* Get the encapsulated protocol offset and size */
	enc_packet = ip_packet + iphdr_size;
	enc_size = ip_size - iphdr_size;

	/* Put the IP source and dest addresses in a struct in_addr */
	memcpy(&src, &(ip.saddr), sizeof(struct in_addr));
	memcpy(&dst, &(ip.daddr), sizeof(struct in_addr));

	switch(ip.protocol) {
	case IPPROTO_ICMP:
		match = recv_icmp(enc_packet, enc_size);
		break;
	case IPPROTO_UDP:
		match = recv_udp(enc_packet, enc_size);
		break;
	case IPPROTO_TCP:
		match = recv_tcp(enc_packet, enc_size);
		break;
	default:
		return;
	}

	if (match)
		recv_pkt++;

	/* Dump the packet in hex */
	if (opt_hexdump && match && !opt_quiet)
		hex_dump(ip_packet, ip_size);

	/* Dump printable characters inside the packet */
	if (opt_contdump && match && !opt_quiet)
		human_dump(ip_packet, ip_size);

	/* Display IP options */
	if (match && opt_rroute && !opt_quiet)
		display_ipopt(ip_packet);

	/* --stop-tr stops hping in traceroute mode when the
	 * first not ICMP time exceeded packet is received */
	if (opt_traceroute && opt_tr_stop && match) {
		struct myicmphdr icmp;

		if (ip.protocol != IPPROTO_ICMP)
			print_statistics(0);
		if (enc_size >= ICMPHDR_SIZE) {
			memcpy(&icmp, enc_packet, sizeof(icmp));
			if (icmp.type != 11)
				print_statistics(0);
		}
	}

	/* if the count was reached exit now */
	if (count != -1 && count == recv_pkt)
		print_statistics(0);
}

void log_ip(int status, int sequence)
{
	int rel_id, ip_id;

	/* get ip->id */
	if (opt_winid_order)
		ip_id = ip.id;
	else
		ip_id = htons(ip.id);

	if (status == S_RECV)
		printf("DUP! ");

	if (opt_relid)
		rel_id = relativize_id(sequence, &ip_id);
	else
		rel_id = 0;
	printf("len=%d ip=%s ttl=%d %sid%s%d ", ip_size, inet_ntoa(src),
			ip.ttl,
			(ntohs(ip.frag_off) ? "DF " : ""),
			(rel_id ? "=+" : "="), ip_id);
	if (opt_verbose && !opt_quiet)
		printf("tos=%x iplen=%u\n", ip.tos, htons(ip.tot_len));
}

void log_icmp_ts(void *ts)
{
	struct icmp_tstamp_data icmp_tstamp;
       
	memcpy(&icmp_tstamp, ts, sizeof(icmp_tstamp));
	printf("ICMP timestamp: Originate=%u Receive=%u Transmit=%u\n",
		(unsigned int) ntohl(icmp_tstamp.orig),
		(unsigned int) ntohl(icmp_tstamp.recv),
		(unsigned int) ntohl(icmp_tstamp.tran));
	printf("ICMP timestamp RTT tsrtt=%lu\n\n",
		(long unsigned int) (get_midnight_ut_ms() 
                                     - ntohl(icmp_tstamp.orig)));
}

void log_icmp_addr(void *addrptr)
{
	unsigned char *addr = addrptr;
	printf("ICMP address mask: icmpam=%u.%u.%u.%u\n\n",
       		addr[0], addr[1], addr[2], addr[3]);
}

void log_traceroute(void *packet, int size, int icmp_code)
{
	static unsigned char old_src_addr[4] = { 0, 0, 0, 0 };
	int sequence = 0, retval;
	float rtt;

	if (!opt_tr_keep_ttl && !memcmp(&ip.saddr, old_src_addr, 4))
		return;

	retval = icmp_unreach_rtt(packet+ICMPHDR_SIZE, size-ICMPHDR_SIZE,
					&sequence, &rtt);
	memcpy(old_src_addr, &ip.saddr, sizeof(ip.saddr));
	printf("hop=%d ", src_ttl);
	fflush(stdout);
	log_icmp_timeexc(inet_ntoa(src), icmp_code);
	if (retval != -1)
		printf("hop=%d hoprtt=%.1f ms\n",
				src_ttl, rtt);
	if (!opt_tr_keep_ttl)
		src_ttl++;
}

int recv_icmp(void *packet, size_t size)
{
	struct myicmphdr icmp;
	struct myiphdr quoted_ip;

	/* Check if the packet can contain the ICMP header */
	if (size < ICMPHDR_SIZE) {
		printf("[|icmp]\n");
		return 0;
	}
	memcpy(&icmp, packet, sizeof(icmp));

	/* --------------------------- *
	 * ICMP ECHO/TIMESTAMP/ADDRESS *
	 * --------------------------- */
	if ((icmp.type == ICMP_ECHOREPLY  ||
	     icmp.type == ICMP_TIMESTAMPREPLY ||
	     icmp.type == ICMP_ADDRESSREPLY) &&
		icmp.un.echo.id == (getpid() & 0xffff))
	{
		int icmp_seq = icmp.un.echo.sequence;
		int status;
		float ms_delay;

		recv_beep();
		/* obtain round trip time */
		status = rtt(&icmp_seq, 0, &ms_delay);
		log_ip(status, icmp_seq);

		printf("icmp_seq=%d rtt=%.1f ms\n", icmp_seq, ms_delay);
		if (icmp.type == ICMP_TIMESTAMPREPLY) {
			if ((size - ICMPHDR_SIZE) >= 12)
				log_icmp_ts(packet+ICMPHDR_SIZE);
			else
				printf("[|icmp timestamp]\n");
		} else if (icmp.type == ICMP_ADDRESSREPLY) {
			if ((size - ICMPHDR_SIZE) >= 4)
				log_icmp_addr(packet+ICMPHDR_SIZE);
			else
				printf("[|icmp subnet address]\n");
		}
		return 1;
	}
	/* ------------------------------------ *
	 * ICMP DEST UNREACHABLE, TIME EXCEEDED *
	 * ------------------------------------ */
	else if (icmp.type == 3 || icmp.type == 11) {
		if ((size - ICMPHDR_SIZE) < sizeof(struct myiphdr)) {
			printf("[|icmp quoted ip]\n");
			return 0;
		}
		memcpy(&quoted_ip, packet+ICMPHDR_SIZE, sizeof(quoted_ip));
		if (memcmp(&quoted_ip.daddr, &remote.sin_addr,
			sizeof(quoted_ip.daddr)) ||
		    memcmp(&ip.daddr, &local.sin_addr, sizeof(ip.daddr)))
			return 0; /* addresses don't match */
		/* Now we can handle the specific type */
		switch(icmp.type) {
		case 3:
			if (!opt_quiet)
				log_icmp_unreach(inet_ntoa(src), icmp.code);
			return 1;
		case 11:
			if (opt_traceroute)
				log_traceroute(packet, size, icmp.code);
			else
				log_icmp_timeexc(inet_ntoa(src), icmp.code);
			return 1;
		}
	}

	return 0; /* don't match */
}

int recv_udp(void *packet, size_t size)
{
	struct myudphdr udp;
	int sequence = 0, status;
	float ms_delay;

	if (size < UDPHDR_SIZE) {
		printf("[|udp]\n");
		return 0;
	}
	memcpy(&udp, packet, sizeof(udp));

	/* check if the packet matches */
	if ((ntohs(udp.uh_sport) == dst_port) ||
	    (opt_force_incdport &&
	     (ntohs(udp.uh_sport) >= base_dst_port &&
	      ntohs(udp.uh_sport) <= dst_port)))
	{
		recv_beep();
		status = rtt(&sequence, ntohs(udp.uh_dport), &ms_delay);
		if (!opt_quiet) {
			log_ip(status, sequence);
			printf("seq=%d rtt=%.1f ms\n", sequence, ms_delay);
		}
		if (opt_incdport && !opt_force_incdport)
			dst_port++;
		return 1;
	}
	return 0;
}

int recv_tcp(void *packet, size_t size)
{
	struct mytcphdr tcp;
	int sequence = 0, status;
	float ms_delay;
	char flags[16];

	if (size < TCPHDR_SIZE) {
		printf("[|tcp]\n");
		return 0;
	}
	memcpy(&tcp, packet, sizeof(tcp));

	/* check if the packet matches */
	if ((ntohs(tcp.th_sport) == dst_port) ||
	    (opt_force_incdport &&
	     (ntohs(tcp.th_sport) >= base_dst_port &&
	      ntohs(tcp.th_sport) <= dst_port)))
	{
		recv_beep();
		tcp_exitcode = tcp.th_flags;

		status = rtt(&sequence, ntohs(tcp.th_dport), &ms_delay);

		if (opt_seqnum) {
			static __u32 old_th_seq = 0;
			__u32 seq_diff, tmp;

			tmp = ntohl(tcp.th_seq);
			if (tmp >= old_th_seq)
				seq_diff = tmp - old_th_seq;
			else
				seq_diff = (4294967295U - old_th_seq)
					+ tmp;
			old_th_seq = tmp;
			printf("%10lu +%lu\n",
				(unsigned long) tmp,
				(unsigned long) seq_diff);
			goto out;
		}

		if (opt_quiet)
			goto out;

		flags[0] = '\0';
		if (tcp.th_flags & TH_RST)  strcat(flags, "R");
		if (tcp.th_flags & TH_SYN)  strcat(flags, "S");
		if (tcp.th_flags & TH_ACK)  strcat(flags, "A");
		if (tcp.th_flags & TH_FIN)  strcat(flags, "F");
		if (tcp.th_flags & TH_PUSH) strcat(flags, "P");
		if (tcp.th_flags & TH_URG)  strcat(flags, "U");
		if (tcp.th_flags & TH_X)    strcat(flags, "X");
		if (tcp.th_flags & TH_Y)    strcat(flags, "Y");
		if (flags[0] == '\0')    strcat(flags, "none");

		log_ip(status, sequence);
		printf("sport=%d flags=%s seq=%d win=%d rtt=%.1f ms\n",
			ntohs(tcp.th_sport), flags, sequence,
			ntohs(tcp.th_win), ms_delay);

		if (opt_verbose) {
			printf("seq=%lu ack=%lu sum=%x urp=%u\n\n",
					(unsigned long) ntohl(tcp.th_seq),
					(unsigned long) ntohl(tcp.th_ack),
					tcp.th_sum, ntohs(tcp.th_urp));
		}

		/* Get and log the TCP timestamp */
		if (opt_tcp_timestamp && status != S_RECV)
			print_tcp_timestamp(packet, size, (int)ms_delay);
out:
		if (opt_incdport && !opt_force_incdport)
			dst_port++;
		return 1;
	}
	return 0;
}

/* Try to extract information about the original packet from the
 * ICMP error to obtain the round time trip
 *
 * Note that size is the the packet size starting from the
 * IP packet quoted in the ICMP error, it may be negative
 * if the ICMP is broken */
int icmp_unreach_rtt(void *quoted_ip, int size, int *seqp, float *ms_delay)
{
	int src_port;
	int sequence = 0;
	int quoted_iphdr_size;
	struct myudphdr udp;
	struct myicmphdr icmp;
	struct myiphdr qip;

	/* The user specified --no-rtt */
	if (opt_tr_no_rtt)
		return -1;

	if (size < sizeof(struct myiphdr))
		return -1;
	memcpy(&qip, quoted_ip, sizeof(struct myiphdr));
	quoted_iphdr_size = qip.ihl << 2;
	/* Ok, enough room, try to get the rtt,
	 * but check if the original packet was an UDP/TCP one */
	if (qip.protocol == IPPROTO_TCP ||
	    qip.protocol == IPPROTO_UDP) {
		/* We need at least 2 bytes of the quoted UDP/TCP header
		 * for the source port */
		if ((size - quoted_iphdr_size) < 2)
			return -1;

		/* Use the UDP header for both UDP and TCP, they are
		* the same in the 4 first bytes (source and dest port) */
		memcpy(&udp, quoted_ip+quoted_iphdr_size, sizeof(udp));
		src_port = htons(udp.uh_sport);
		return rtt(&sequence, src_port, ms_delay);
	} else if (qip.protocol == IPPROTO_ICMP) {
		int s;

		/* We need the whole 8 byte ICMP header to get
		 * the sequence field, also the type must be
		 * ICMP_ECHO */
		memcpy(&icmp, quoted_ip+quoted_iphdr_size, sizeof(icmp));
		if ((size - quoted_iphdr_size) < 8 ||
		    icmp.type != ICMP_ECHO)
			return -1;

		s = icmp.un.echo.sequence;
		return rtt(&s, 0, ms_delay);
	}
	return -1; /* no way */
}

void clock_skew(int hz, __u32 tstamp, int rttms)
{
    long long tstampms = tstamp*(1000/hz);
    long long tstampms2; /* tstamp after rtt correction */
    long long currdelta; /* current delta */
    long long localms; /* local clock */
    static long long *deltavect = NULL; /* delta vector, for samples collection */
    static long long *deltartt = NULL; /* rtt of every tstamp packet */

    /* Deltas in deltavect with deltartt information are used to
     * get samples of the time difference between the local host and
     * the remote host. Every cs_vector_len packets caputed in the
     * deltvact array are used to estimate the time delta that's
     * put in turrn into the sample vector. */

    static int deltanum = 0; /* number of deltas in deltavect */
    static long long *sample = NULL; /* error corrected delta vector */
    static long long *samplelocal = NULL; /* local time of captured delta vector */
    static int samplelen = 0;

    if (deltavect == NULL) {
        deltavect = malloc(sizeof(*deltavect)*cs_vector_len);
        deltartt = malloc(sizeof(*deltartt)*cs_vector_len);
        if (deltavect == NULL) {
            fprintf(stderr, "Out of memory in clock_skew()\n");
            exit(1);
        }
        deltanum = 0;
    }

    printf("  Clock skew detection...\n");
    printf("    hz: %d\n", hz);
    printf("    received tstamp (converted in ms according to hz): %lld\n", tstampms);
    printf("    rtt in milliseconds: %d\n", rttms);

    tstampms2 = tstampms-(rttms/2); /* Assuming symmetric path for packets... */
    localms = mstime();
    currdelta = localms-tstampms2;
    printf("    tstamp-(rtt/2): %lld\n", tstampms2);
    printf("    local/remote clock delta: %lld\n", currdelta);
    deltavect[deltanum] = currdelta;
    deltartt[deltanum] = rttms;
    deltanum++;

    /* When cs_vector_len packets are captured we can estimate
     * the current clock difference between our local PC and the remote
     * host. We call every delta estimation a "sample" */
    if (deltanum == cs_vector_len) {
        long long sum = 0;
        unsigned long long minrtt;
        int j, validpackets;

        /* First we check what's the minimum RTT. We'll later
         * discard packets with an RTT too high compared to
         * the minimum one as this are source of errors. */
        minrtt = deltartt[0];
        for (j = 1; j < cs_vector_len; j++)
            if (deltartt[j] < minrtt) minrtt = deltartt[j];

        /* Now we can average the deltavect elements to get a
         * sample. In the process information from packets with
         * an rtt greater than 10% of the the min rtt are discarded */

        validpackets = 0;
        for (j = 0; j < cs_vector_len; j++) {
            if (minrtt > 10 && (deltartt[j]-minrtt > minrtt/10)) {
                printf("    # Not used packet %d/%d with rtt %lld (max acceptable %lld)\n", j+1, cs_vector_len, deltartt[j], minrtt+(minrtt/10));
                continue;
            }
            sum += deltavect[j];
            validpackets++;
        }

        deltanum = 0; /* reset the counter anyway */
        if (validpackets) {
            sum /= validpackets;
            printf("    >> error corrected delta: %lld** (based on %d of %d packets)\n", sum, validpackets, cs_vector_len);
            sample = realloc(sample,sizeof(*sample)*(samplelen+1));
            samplelocal = realloc(samplelocal,sizeof(*samplelocal)*(samplelen+1));
            if (!sample || !samplelocal) {
                fprintf(stderr, "Out of memory in clock_skew()\n");
                exit(1);
            }
            sample[samplelen] = sum;
            samplelocal[samplelen] = mstime();
            samplelen++;
        }
    }

    /* If we have enough data to start to compute the
     * skew, compute it and display the information. */
    if (samplelen > cs_window_shift &&
        samplelocal[samplelen-1]-samplelocal[cs_window_shift-1] > cs_window*1000)
    {
        int i = samplelen-2, j;
        long long skew, skewsum = 0, delta, localdelta = 0;

        /* Search the first sample from right to left so that
         * the local time difference is >= the selected window */
        while(samplelocal[samplelen-1]-samplelocal[i]<cs_window*1000)
            i--;
        /* Now we can calculate the skew for multiple pairs with
         * the given time distance (window), and do the average
         * in order to get more accurate data */
        printf("    Latest observed skews (no shift correction) ( ");
        for (j = cs_window_shift-1; j >= 0; j--) {
            localdelta = samplelocal[samplelen-1-j]-samplelocal[i-j];
            delta = sample[samplelen-1-j]-sample[i-j];
            skew = (delta*1000000)/localdelta; /* nanoseconds */
            printf("%lld ", skew);
            skewsum += skew;
        }
        printf(") next line is the average\n");
        skewsum /= cs_window_shift;
        printf("    %d sec. window SKEW: %lld nanoseconds/second\n", cs_window, skewsum);
        /* Compute the SKEW from the full range of samples we have */
        skewsum = 0;
        for (j = 0; j < cs_window_shift; j++) {
            localdelta = samplelocal[samplelen-1-j]-samplelocal[cs_window_shift-1-j];
            delta = sample[samplelen-1-j]-sample[cs_window_shift-1-j];
            skew = (delta*1000000)/localdelta; /* nanoseconds */
            skewsum += skew;
        }
        skewsum /= cs_window_shift;
        printf(">   %lld sec. window SKEW: %lld nanoseconds/second\n", localdelta/1000, skewsum);
    } else {
        printf("  !! Not enough data to show reliable skew, wait please...\n");
        if (samplelen > 1) {
            long long skew = 0, delta, localdelta;
            localdelta = samplelocal[samplelen-1]-samplelocal[0];
            delta = sample[samplelen-1]-sample[0];
            skew = (delta*1000000)/localdelta;
            printf("\n  Early info just to take you happy... ;)\n");
            printf("     early unreliable skew guess: %lld nanoseconds per second\n", skew);
            printf("     early guess localdelta: %lld ms\n", localdelta);
            printf("     early delta: %lld ms\n", delta);
        }
    }
    printf("  collected %d/%d deltas for next sample\n",
            deltanum, cs_vector_len);
}

void print_tcp_timestamp(void *tcp, int tcpsize, int rttms)
{
	int optlen;
	unsigned char *opt;
	__u32 tstamp = 0, echo;
	static __u32 first_tstamp = 0;
        static unsigned long long first_mstime = 0;
	struct mytcphdr tmptcphdr;
	unsigned int tcphdrlen;

	if (tcpsize < TCPHDR_SIZE)
		return;
	memcpy(&tmptcphdr, tcp, sizeof(struct mytcphdr));
	tcphdrlen = tmptcphdr.th_off * 4;

	/* bad len or no options in the TCP header */
	if (tcphdrlen <= 20 || tcphdrlen < tcpsize)
		return;
	optlen = tcphdrlen - TCPHDR_SIZE;
	opt = (unsigned char*)tcp + TCPHDR_SIZE; /* skips the TCP fix header */
	while(optlen) {
		switch(*opt) {
		case 0: /* end of option */
			return;
		case 1: /* noop */
			opt++;
			optlen--;
			continue;
		default:
			if (optlen < 2)
				return;
			if (opt[1] > optlen)
				return;
			if (opt[0] != 8) { /* not timestamp */
				optlen -= opt[1];
				opt += opt[1];
				continue;
			}
			/* timestamp found */
			if (opt[1] != 10) /* bad len */
				return;
			memcpy(&tstamp, opt+2, 4);
			memcpy(&echo, opt+6, 4);
			tstamp = ntohl(tstamp);
			echo = ntohl(echo);
			goto found;
		}
	}
found:
	printf("  TCP timestamp: tcpts=%u\n", tstamp);
	if (first_tstamp) {
		int tsdiff;
		int hz_set[] = { 2, 10, 100, 1000, 0 };
		int hzdiff = -1;
		int hz = 0, sec;
		int days, hours, minutes;
                unsigned long long mswait;

                mswait = mstime()-first_mstime;
                tsdiff = (int)(((long long)(tstamp - first_tstamp)*1000)/mswait);
		if (tsdiff > 0) {
			int i = 0;
			while(hz_set[i]) {
				if (hzdiff == -1) {
					hzdiff = ABS(tsdiff-hz_set[i]);
					hz = hz_set[i];
				} else if (hzdiff > ABS(tsdiff-hz_set[i])) {
					hzdiff = ABS(tsdiff-hz_set[i]);
					hz = hz_set[i];
				}
				i++;
			}
			printf("  HZ seems hz=%d (%d measured)\n", hz, tsdiff);
			sec = tstamp/hz; /* Get the uptime in seconds */
			days = sec / (3600*24);
			sec %= 3600*24;
			hours = sec / 3600;
			sec %= 3600;
			minutes = sec / 60;
			sec %= 60;
			printf("  System uptime seems: %d days, %d hours, "
			       "%d minutes, %d seconds\n",
			       		days, hours, minutes, sec);
		}
                if (hz > 0 && opt_clock_skew) clock_skew(hz,tstamp,rttms);
	} else {
	    first_tstamp = tstamp;
            first_mstime = mstime();
        }
	printf("\n");
}

/* This function is exported to listen.c also */
int read_packet(void *packet, int size)
{
	size = pcap_recv(packet, size);
	if (size == -1)
		perror("[wait_packet] pcap_recv()");
	return size;
}

void hex_dump(void *packet, int size)
{
	unsigned char *byte = packet;
	int count = 0;

	printf("\t\t");
	for (; byte < (unsigned char*) (packet+size); byte++) {
		count++;
		printf("%02x", *byte);
		if (count % 2 == 0) printf(" ");
		if (count % 16 == 0) printf("\n\t\t");
	}
	printf("\n\n");
}

void human_dump(void *packet, int size)
{
	unsigned char *byte = packet;
	int count = 0;

	printf("\t\t");
	for (; byte < (unsigned char*) (packet+size); byte++) {
		count ++;
		if (isprint(*byte))
			printf("%c", *byte);
		else
			printf(".");
		if (count % 32 == 0) printf("\n\t\t");
	}
	printf("\n\n");
}

void handle_hcmp(char *packet, int size)
{
	char *p;
	struct hcmphdr hcmph;
	unsigned int seq;

	/* Search for the reverse signature inside the packet */
	if ((p = memstr(packet, rsign, size)) == NULL)
		return;

	if (opt_debug)
		fprintf(stderr, "DEBUG: HCMP received\n");

	p+=strlen(rsign);
	if ((size-(packet-p)) < sizeof(struct hcmphdr)) {
		if (opt_verbose || opt_debug)
			fprintf(stderr, "bad HCMP len received\n");
		return;
	}

	memcpy(&hcmph, p, sizeof(hcmph));

	switch(hcmph.type) {
	case HCMP_RESTART:
		seq = ntohs(hcmph.typedep.seqnum);
		src_id = seq; /* set the id */
		datafiller(NULL, seq); /* data seek */
		if (opt_debug)
			printf("DEBUG: HCMP restart from %d\n",
					seq);
		return;
	case HCMP_SOURCE_QUENCH:
	case HCMP_SOURCE_STIRUP:
		printf("HCMP source quench/stirup received\n");
		return;
	default:
		if (opt_verbose || opt_debug)
			fprintf(stderr, "bad HCMP type received\n");
		return;
	}
}
