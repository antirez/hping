/* 
 * $smu-mark$ 
 * $name: usage.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:50 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: usage.c,v 1.2 2004/06/18 09:53:11 antirez Exp $ */

#include <stdlib.h>
#include <stdio.h>

void	show_usage(void)
{
	printf(
"usage: hping host [options]\n"
"  -h  --help      show this help\n"
"  -v  --version   show version\n"
"  -c  --count     packet count\n"
"  -i  --interval  wait (uX for X microseconds, for example -i u1000)\n"
"      --fast      alias for -i u10000 (10 packets for second)\n"
"      --faster    alias for -i u1000 (100 packets for second)\n"
"      --flood	   sent packets as fast as possible. Don't show replies.\n"
"  -n  --numeric   numeric output\n"
"  -q  --quiet     quiet\n"
"  -I  --interface interface name (otherwise default routing interface)\n"
"  -V  --verbose   verbose mode\n"
"  -D  --debug     debugging info\n"
"  -z  --bind      bind ctrl+z to ttl           (default to dst port)\n"
"  -Z  --unbind    unbind ctrl+z\n"
"      --beep      beep for every matching packet received\n"
"Mode\n"
"  default mode     TCP\n"
"  -0  --rawip      RAW IP mode\n"
"  -1  --icmp       ICMP mode\n"
"  -2  --udp        UDP mode\n"
"  -8  --scan       SCAN mode.\n"
"                   Example: hping --scan 1-30,70-90 -S www.target.host\n"
"  -9  --listen     listen mode\n"
"IP\n"
"  -a  --spoof      spoof source address\n"
"  --rand-dest      random destionation address mode. see the man.\n"
"  --rand-source    random source address mode. see the man.\n"
"  -t  --ttl        ttl (default 64)\n"
"  -N  --id         id (default random)\n"
"  -W  --winid      use win* id byte ordering\n"
"  -r  --rel        relativize id field          (to estimate host traffic)\n"
"  -f  --frag       split packets in more frag.  (may pass weak acl)\n"
"  -x  --morefrag   set more fragments flag\n"
"  -y  --dontfrag   set dont fragment flag\n"
"  -g  --fragoff    set the fragment offset\n"
"  -m  --mtu        set virtual mtu, implies --frag if packet size > mtu\n"
"  -o  --tos        type of service (default 0x00), try --tos help\n"
"  -G  --rroute     includes RECORD_ROUTE option and display the route buffer\n"
"  --lsrr           loose source routing and record route\n"
"  --ssrr           strict source routing and record route\n"
"  -H  --ipproto    set the IP protocol field, only in RAW IP mode\n"
"ICMP\n"
"  -C  --icmptype   icmp type (default echo request)\n"
"  -K  --icmpcode   icmp code (default 0)\n"
"      --force-icmp send all icmp types (default send only supported types)\n"
"      --icmp-gw    set gateway address for ICMP redirect (default 0.0.0.0)\n"
"      --icmp-ts    Alias for --icmp --icmptype 13 (ICMP timestamp)\n"
"      --icmp-addr  Alias for --icmp --icmptype 17 (ICMP address subnet mask)\n"
"      --icmp-help  display help for others icmp options\n"
"UDP/TCP\n"
"  -s  --baseport   base source port             (default random)\n"
"  -p  --destport   [+][+]<port> destination port(default 0) ctrl+z inc/dec\n"
"  -k  --keep       keep still source port\n"
"  -w  --win        winsize (default 64)\n"
"  -O  --tcpoff     set fake tcp data offset     (instead of tcphdrlen / 4)\n"
"  -Q  --seqnum     shows only tcp sequence number\n"
"  -b  --badcksum   (try to) send packets with a bad IP checksum\n"
"                   many systems will fix the IP checksum sending the packet\n"
"                   so you'll get bad UDP/TCP checksum instead.\n"
"  -M  --setseq     set TCP sequence number\n"
"  -L  --setack     set TCP ack\n"
"  -F  --fin        set FIN flag\n"
"  -S  --syn        set SYN flag\n"
"  -R  --rst        set RST flag\n"
"  -P  --push       set PUSH flag\n"
"  -A  --ack        set ACK flag\n"
"  -U  --urg        set URG flag\n"
"  -X  --xmas       set X unused flag (0x40)\n"
"  -Y  --ymas       set Y unused flag (0x80)\n"
"  --tcpexitcode    use last tcp->th_flags as exit code\n"
"  --tcp-timestamp  enable the TCP timestamp option to guess the HZ/uptime\n"
"Clock skew detection\n"
"  --clock-skew     enable clock skew detection. Try with -S against open port\n"
"  --clock-skew-win window of time (in seconds) for CS detection. Default 300\n"
"  --clock-skew-shift timestamp samples to use for error correction. Default 5\n"
"  --clock-skew-packets-per-sample # of packets to extract a sample. Default 10\n"
"Common\n"
"  -d  --data       data size                    (default is 0)\n"
"  -E  --file       data from file\n"
"  -e  --sign       add 'signature'\n"
"  -j  --dump       dump packets in hex\n"
"  -J  --print      dump printable characters\n"
"  -B  --safe       enable 'safe' protocol\n"
"  -u  --end        tell you when --file reached EOF and prevent rewind\n"
"  -T  --traceroute traceroute mode              (implies --bind and --ttl 1)\n"
"  --tr-stop        Exit when receive the first not ICMP in traceroute mode\n"
"  --tr-keep-ttl    Keep the source TTL fixed, useful to monitor just one hop\n"
"  --tr-no-rtt	    Don't calculate/show RTT information in traceroute mode\n"
"ARS packet description (new, unstable)\n"
"  --apd-send       Send the packet described with APD (see docs/APD.txt)\n"
	);
	exit(0);
};

void tos_help(void)
{
	printf(
"tos help:\n"
"          TOS Name                Hex Value           Typical Uses\n"
"\n"
"       Minimum Delay                 10               ftp, telnet\n"
"       Maximum Throughput            08               ftp-data\n"
"       Maximum Reliability           04               snmp\n"
"       Minimum Cost                  02               nntp\n"
	);
	exit(0);
}

void icmp_help(void)
{
	printf(
"ICMP help:\n"
" ICMP concerned packet options:\n"
"  --icmp-ipver     set ip version               ( default 4 )\n"
"  --icmp-iphlen    set ip header lenght         ( default IPHDR_SIZE >> 2)\n"
"  --icmp-iplen     set ip total lengtht         ( default real lenght )\n"
"  --icmp-ipid      set ip id                    ( default random )\n"
"  --icmp-ipproto   set ip protocol              ( default IPPROTO_TCP )\n"
"  --icmp-ipsrc     set ip source                ( default 0.0.0.0 )\n"
"  --icmp-ipdst     set ip destination           ( default 0.0.0.0 )\n"
"  --icmp-srcport   set tcp/udp source port      ( default random )\n"
"  --icmp-dstport   set tcp/udp destination port ( default random )\n"
"  --icmp-cksum     set icmp checksum            ( default the right cksum)\n"
	);
	exit(0);
}

void route_help(void)
{
    printf(
"route help:\n"
"	A route has the following format: [ptr:]IP1[/IP2[/IP3...]]\n"
"	where ptr is the exact value of the pointer that will be used for the IP\n"
"	option (be careful, no check is performed on this pointer), and defaults\n"
"	to 8, or 4 if provided route is too short for 8;\n"
"	and each IPx field is an IP address to include in the source route.\n");
}
