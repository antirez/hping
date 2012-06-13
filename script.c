/* Hping's TCL scripting support
 * Copyright (C) 2003 Salvatore Sanfilippo
 * All Rights Reserved */

/* URGENT TODO:
 *
 * link header size in recv_handlers, -1 means autodetection. */

/* $Id: script.c,v 1.20 2004/05/29 06:48:13 antirez Exp $ */

#ifdef USE_TCL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sched.h>

#include <sys/ioctl.h>
#include <pcap.h>
#include <net/bpf.h>

#include "release.h"
#include "hping2.h"
#include "ars.h"
#include "interface.h"
#include "apdutils.h"
#include "sbignum.h"

#define HPING_IF_MAX	8

/* ----------------------- hping recv handlers code ------------------------- */
struct recv_handler {
	Tcl_Interp *rh_interp; /* If not null has [hpingevent] handler. */
	Tcl_Obj *rh_handlerscript; /* the [hpingevent] handler script. */
	char rh_ifname[HPING_IFNAME_LEN];
	int rh_linkhdrsize; /* -1 means autodetection */
	pcap_t *rh_pcapfp;
	char rh_pcap_errbuf[PCAP_ERRBUF_SIZE];
};

struct recv_handler recv_handlers[HPING_IFACE_MAX];

/* Recv handlers intialization */
static void HpingRecvInit(struct recv_handler *ra, int len)
{
	memset(ra, 0, sizeof(*ra)*len);
}

static void HpingRecvCloseHandler(struct recv_handler *ra)
{
	ra->rh_ifname[0] = '\0';
	if (ra->rh_interp != NULL) {
		Tcl_DeleteFileHandler(pcap_fileno(ra->rh_pcapfp));
		Tcl_DecrRefCount(ra->rh_handlerscript);
	}
	pcap_close(ra->rh_pcapfp);
	ra->rh_interp = NULL;
}

static struct recv_handler *HpingRecvGetHandler(struct recv_handler *ra, int len, char *ifname, Tcl_Interp *interp)
{
	int i;
	#if (!defined OSTYPE_LINUX) && (!defined __sun__)
	int on = 1;
	#endif

	for (i = 0; i < len; i++) {
		if (!ra[i].rh_ifname[0])
			break;
		if (!strcmp(ra[i].rh_ifname, ifname))
			return ra+i;
	}
	/* Not found, need to open it */
	if (i == len) {
		/* XXX: with hping setfilter this is broken */
		/* All the slots are full, make space at the end */
		HpingRecvCloseHandler(ra+(len-1));
		i--;
	}
	/* Open a new handler */
	ra[i].rh_pcapfp = pcap_open_live(ifname, 99999, 0, 1, ra[i].rh_pcap_errbuf);
	if (ra[i].rh_pcapfp == NULL)
		return NULL;
	#if (!defined OSTYPE_LINUX) && (!defined __sun__)
	/* Return the packets to userspace as fast as possible */
	if (ioctl(pcap_fileno(ra[i].rh_pcapfp), BIOCIMMEDIATE, &on) == -1) {
		/* XXX non-critical error */
	}
	#endif
	strlcpy(ra[i].rh_ifname, ifname, HPING_IFNAME_LEN);
	ra[i].rh_interp = NULL;
	ra[i].rh_linkhdrsize = dltype_to_lhs(pcap_datalink(ra[i].rh_pcapfp));
	return ra+i;
}

/* ----------------------------- Sub commands ------------------------------- */
/* hping resolve hostname */
static int HpingResolveCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct sockaddr_in saddr;
	char *hostname;
	Tcl_Obj *result;

	result = Tcl_GetObjResult(interp);
	if (objc != 3 && objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "?-ptr? hostname");
		return TCL_ERROR;
	}
	if (objc == 4) {
		char *ptropt, *ipaddr;
		struct in_addr ina;
		struct hostent *he;

		ptropt = Tcl_GetStringFromObj(objv[2], NULL);
		if (strcmp(ptropt, "-ptr")) {
			Tcl_SetStringObj(result, "The only valid option for resolve is -ptr", -1);
			return TCL_ERROR;
		}
		ipaddr = Tcl_GetStringFromObj(objv[3], NULL);
		if (inet_aton(ipaddr, &ina) == 0) {
			Tcl_SetStringObj(result, "Invalid IP address: ", -1);
			Tcl_AppendStringsToObj(result, ipaddr, NULL);
			return TCL_ERROR;
		}
		he = gethostbyaddr((const char*)&ina.s_addr, sizeof(ina.s_addr), AF_INET);
		if (he == NULL)
			Tcl_SetStringObj(result, ipaddr, -1);
		else
			Tcl_SetStringObj(result, he->h_name, -1);
		return TCL_OK;
	}
	hostname = Tcl_GetStringFromObj(objv[2], NULL);
	if (resolve_addr((struct sockaddr*)&saddr, hostname) != -1) {
		Tcl_SetStringObj(result, inet_ntoa(saddr.sin_addr), -1);
		return TCL_OK;
	} else {
		Tcl_SetStringObj(result, "Unable to resolve: ", -1);
		Tcl_AppendStringsToObj(result, hostname, NULL);
		return TCL_ERROR;
	}
	return TCL_OK;
}

/* raw socket is shared between different functions, but note
 * that it gets open only once needed. This makes possible
 * to run hping scripts doing unprivileged work without root
 * access. */
static int rawsocket = -1;

/* hping send ?-nocompile? pktdescr */
static int HpingSendCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct ars_packet p;
	int nocompile = 0;
	Tcl_Obj *result;
	char *packetdescr, *noc;

	if (objc != 3 && objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "?-nocompile? packet");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	if (objc == 4) {
		noc = Tcl_GetStringFromObj(objv[2], NULL);
		if (strcmp(noc, "-nocompile")) {
			Tcl_SetStringObj(result, "Invalid option", -1);
			return TCL_ERROR;
		}
		nocompile = 1;
		objv++;
	}
	ars_init(&p);
	packetdescr = Tcl_GetStringFromObj(objv[2], NULL);
	if (rawsocket == -1) {
		rawsocket = ars_open_rawsocket(&p);
		if (rawsocket == -ARS_ERROR) {
			Tcl_SetStringObj(result, "Error opening raw socket: ", -1);
			Tcl_AppendStringsToObj(result, strerror(errno), NULL);
			ars_destroy(&p);
			return TCL_ERROR;
		}
	}
	if (ars_d_build(&p, packetdescr) != -ARS_OK) {
		Tcl_SetStringObj(result, "Packet building error: '", -1);
		Tcl_AppendStringsToObj(result, p.p_error,"' in packet ", packetdescr, NULL);
		ars_destroy(&p);
		return TCL_ERROR;
	}
	if (!nocompile) {
		if (ars_compile(&p) != -ARS_OK) {
			Tcl_SetStringObj(result, "Packet compilation error: ", -1);
			Tcl_AppendStringsToObj(result, p.p_error, NULL);
			ars_destroy(&p);
			return TCL_ERROR;
		}
	}
	if (ars_send(rawsocket, &p, NULL, 0) != -ARS_OK) {
		Tcl_SetStringObj(result, "Sending packet: ", -1);
		Tcl_AppendStringsToObj(result, strerror(errno), NULL);
		ars_destroy(&p);
		return TCL_ERROR;
	}
	ars_destroy(&p);
	return TCL_OK;
}

/* hping sendraw pktdata */
static int HpingSendRawCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	int error;
	Tcl_Obj *result;
	struct sockaddr_in sa;
	char *pkt;
	int pktlen;
	struct ars_iphdr *ip;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 2, objv, "data");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	/* Get packet data */
	pkt = Tcl_GetStringFromObj(objv[2], &pktlen);
	/* Check if the packet is too short */
	if (pktlen < sizeof(struct ars_iphdr)) {
		Tcl_SetStringObj(result, "Packet shorter than IPv4 header", -1);
		return TCL_ERROR;
	}
	ip = (struct ars_iphdr*) pkt;
	/* Get the destination IP from the packet itself */
	sa.sin_family = AF_INET;
	memcpy(&sa.sin_addr.s_addr, &ip->daddr, 4);
	/* Open the rawsocket if needed */
	if (rawsocket == -1) {
		rawsocket = ars_open_rawsocket(NULL);
		if (rawsocket == -ARS_ERROR) {
			Tcl_SetStringObj(result, "Error opening raw socket: ", -1);
			Tcl_AppendStringsToObj(result, strerror(errno), NULL);
			return TCL_ERROR;
		}
	}
	/* ready to send */
	error = sendto(rawsocket, pkt, pktlen, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (error == -1) {
		Tcl_SetStringObj(result, "sendto(2): ", -1);
		Tcl_AppendStringsToObj(result, strerror(errno), NULL);
		return TCL_ERROR;
	}
	return TCL_OK;
}

#define APD_MAX_LEN (65536*2+4096)
char *GetPacketDescription(char *data, int len, int hexdata)
{
	unsigned char *p = (char*)data;
	struct ars_packet pkt;
	char *d = malloc(APD_MAX_LEN);
	char *ret;

	ars_init(&pkt);
	if (hexdata) {
		ars_set_option(&pkt, ARS_OPT_RAPD_HEXDATA);
	}
	if (ars_split_packet(p, len, 0, &pkt) != -ARS_OK) {
		/* FIXME: handle this error properly */
	}
	if (ars_d_from_ars(d, APD_MAX_LEN, &pkt) != -ARS_OK) {
		/* FIXME: handle this error properly */
	}
	ars_destroy(&pkt);
	ret = strdup(d);
	free(d);
	return ret;
}

/* Read a packet with a given timeout.
 * The function returns -1 on error, non zero on a successful
 * read, and 0 when no error occurred but the read must be
 * reiterated (possibly before timeout expired).
 *
 * A zero timeout is valid, and means returns a packet if
 * it is already in the buffer. A negative timeout of -1
 * means to wait forever. */
int pcap_read(pcap_t *, int cnt, pcap_handler, u_char *); /* pcap-int.h */

static int HpingReadPacket(struct recv_handler *ra, char *pkt, int pktlen, int timeout)
{
	struct timeval tv;
	int retval, fd = pcap_fileno(ra->rh_pcapfp);
	struct pcap_pkthdr hdr;
	const unsigned char *d;
	fd_set fs;

	if (timeout >= 0) {
		tv.tv_sec = timeout/1000;
		tv.tv_usec = (timeout%1000)*1000;
	}
	FD_ZERO(&fs);
	FD_SET(fd, &fs);
	if (timeout >= 0)
		retval = select(fd+1, &fs, NULL, NULL, &tv);
	else
		retval = select(fd+1, &fs, NULL, NULL, NULL);
	if (retval == -1) {
		if (errno == EINTR)
			return 0;
		return -1;
	} else if (retval == 0) {
		return 0;
	}
	d = pcap_next(ra->rh_pcapfp, &hdr);
	if (d == NULL)
		return 0;
	if (hdr.caplen > pktlen)
		hdr.caplen = pktlen;
	memcpy(pkt, d, hdr.caplen);
	return hdr.caplen;
}

static int HpingRecvPackets(struct recv_handler *ra, Tcl_Interp *interp, Tcl_Obj *o, int timeout, int maxpackets, int rapd, int hexdata)
{
	time_t startms = milliseconds();
	char _pkt[65535+255];
	char *pkt = _pkt;
	int lhs = ra->rh_linkhdrsize;

	while(1) {
		time_t elapsed;
		int len;

		len = HpingReadPacket(ra, pkt, 65535+255, timeout);
		if (len > 0) {
			Tcl_Obj *element;

			/* Skip the link header */
			pkt += lhs;
			len -= lhs;
			/* Create the entry */
			if (rapd) {
				char *apd;

				apd = GetPacketDescription(pkt, len, hexdata);
				if (!apd)
					return 1;
				element = Tcl_NewStringObj(apd, -1);
				free(apd);
			} else {
				element = Tcl_NewStringObj(pkt, len);
			}
			Tcl_ListObjAppendElement(interp, o, element);
			/* Check if we reached the packets limit */
			if (maxpackets) {
				maxpackets--;
				if (maxpackets == 0)
					return 0;
			}
		}
		if (timeout == 0 && len != 0)
			continue;
		if (timeout >= 0) {
			elapsed = milliseconds() - startms;
			if (elapsed > timeout)
				break;
		}
	}
	return 0;
}

/* hping (recv|recvraw) ifname ?timeout? ?maxpackets?
 * A zero timeout means to return only packets already in queue
 * A negative timeout means to wait forever
 * A zero maxpackets means infinite packets limit.
 *
 * For default timeout is -1, maxpackets is 0 */
static int __HpingRecvCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[], int rapd, int hexdata)
{
	Tcl_Obj *result;
	struct recv_handler *ra;
	char *ifname;
	int timeout = -1; /* specified in ms */
	int maxpackets = 1;

	if (objc != 3 && objc != 4 && objc != 5) {
		Tcl_WrongNumArgs(interp, 2, objv, "ifname ?timeout? ?maxpackets?");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	ifname = Tcl_GetStringFromObj(objv[2], NULL);
	if (objc >= 4)
		Tcl_GetIntFromObj(interp, objv[3], &timeout);
	if (objc == 5)
		Tcl_GetIntFromObj(interp, objv[4], &maxpackets);
	/* FIXME: check if maxpacket == 0 AND timeout == -1. In such
	 * a case the function will never return. */
	ra = HpingRecvGetHandler(recv_handlers, HPING_IFACE_MAX, ifname, interp);
	if (ra == NULL) {
		Tcl_SetStringObj(result, "Unable to open the interface", -1);
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	if (HpingRecvPackets(ra, interp, result, timeout, maxpackets, rapd, hexdata))
		return TCL_ERROR;
	return TCL_OK;
}

/* The two wrappers for the __HpingRecvRawCmd() */
static int HpingRecvRawCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	return __HpingRecvCmd(clientData, interp, objc, objv, 0, 0);
}

static int HpingRecvCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	char *firstarg;
	int hexdata = 0;

	if (objc >= 3) {
		firstarg = Tcl_GetStringFromObj(objv[2], NULL);
		if (!strcmp(firstarg, "-hexdata")) {
			hexdata = 1;
			objc--;
			objv++;
		}
	}
	return __HpingRecvCmd(clientData, interp, objc, objv, 1, hexdata);
}

/* hping getinterfaces */
static int HpingGetInterfacesCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct hpingif ifaces[HPING_IFACE_MAX];
	int found, i;
	Tcl_Obj *result;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 2, objv, "");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	found = hping_get_interfaces(ifaces, HPING_IFACE_MAX);
	if (found == -1) {
		Tcl_SetStringObj(result, "Listing interfaces: ", -1);
		Tcl_AppendStringsToObj(result, strerror(errno), NULL);
		return TCL_ERROR;
	}
	for (i = 0; i < found; i++) {
		struct in_addr ia;
		char mtu[32];
		int j, flags = 0;

		snprintf(mtu, 32, "%d", ifaces[i].hif_mtu);
		Tcl_AppendStringsToObj(result, "{",
				ifaces[i].hif_name, " ",
				mtu, " ", NULL);
		Tcl_AppendStringsToObj(result, "{", NULL);
		for (j = 0; j < ifaces[i].hif_naddr; j++) {
			ia.s_addr = ifaces[i].hif_addr[j];
			Tcl_AppendStringsToObj(result, inet_ntoa(ia), NULL);
			if ((j+1) < ifaces[i].hif_naddr)
				Tcl_AppendStringsToObj(result, " ", NULL);
		}
		Tcl_AppendStringsToObj(result, "}", NULL);
		if (ifaces[i].hif_broadcast) {
			Tcl_AppendStringsToObj(result, " {", NULL);
			for (j = 0; j < ifaces[i].hif_naddr; j++) {
				ia.s_addr = ifaces[i].hif_baddr[j];
				Tcl_AppendStringsToObj(result, inet_ntoa(ia), NULL);
				if ((j+1) < ifaces[i].hif_naddr)
					Tcl_AppendStringsToObj(result, " ", NULL);
			}
			Tcl_AppendStringsToObj(result, "} {", NULL);
		} else {
			Tcl_AppendStringsToObj(result, " {} {", NULL);
		}
		if (ifaces[i].hif_loopback) {
			Tcl_AppendStringsToObj(result, flags ? " " : "", "LOOPBACK", NULL);
			flags++;
		}
		if (ifaces[i].hif_ptp) {
			Tcl_AppendStringsToObj(result, flags ? " " : "", "POINTOPOINT", NULL);
			flags++;
		}
		if (ifaces[i].hif_promisc) {
			Tcl_AppendStringsToObj(result, flags ? " " : "", "PROMISC", NULL);
			flags++;
		}
		if (ifaces[i].hif_broadcast) {
			Tcl_AppendStringsToObj(result, flags ? " " : "", "BROADCAST", NULL);
			flags++;
		}
		if (ifaces[i].hif_nolink) {
			Tcl_AppendStringsToObj(result, flags ? " " : "", "NOLINK", NULL);
			flags++;
		}
		Tcl_AppendStringsToObj(result, "}} ", NULL);
	}
	return TCL_OK;
}

/* hping outifaddr destaddr */
static int HpingGetOutIfAddrCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct sockaddr_in dest, ifaddr;
	Tcl_Obj *result;
	char *deststr;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 2, objv, "destaddr");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	deststr = Tcl_GetStringFromObj(objv[2], NULL);
	if (resolve_addr((struct sockaddr*)&dest, deststr) == -1) {
		Tcl_SetStringObj(result, "Unable to resolve: ", -1);
		Tcl_AppendStringsToObj(result, deststr, NULL);
		return TCL_ERROR;
	}
	if (get_output_if(&dest, &ifaddr) == -1) {
		Tcl_SetStringObj(result, "Can't get output interface: ", -1);
		Tcl_AppendStringsToObj(result, strerror(errno), NULL);
		return TCL_ERROR;
	}
	Tcl_SetStringObj(result, inet_ntoa(ifaddr.sin_addr), -1);
	return TCL_OK;
}

/* hping getfield layer field ?skip? packet */
static int HpingGetFieldCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	char *layer, *field, *value, *packet;
	int skip = 0;
	Tcl_Obj *result;

	if (objc != 5 && objc != 6) {
		Tcl_WrongNumArgs(interp, 2, objv, "layer field ?skip? packet");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	layer = Tcl_GetStringFromObj(objv[2], NULL);
	field = Tcl_GetStringFromObj(objv[3], NULL);
	if (objc == 6) {
		Tcl_GetIntFromObj(interp, objv[4], &skip);
		packet = Tcl_GetStringFromObj(objv[5], NULL);
	} else {
		packet = Tcl_GetStringFromObj(objv[4], NULL);
	}
	value = ars_d_field_get(packet, layer, field, skip);
	if (value) {
		Tcl_SetStringObj(result, value, -1);
		free(value);
	}
	return TCL_OK;
}

/* hping hasfield layer field ?skip? packet */
static int HpingHasFieldCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	char *layer, *field, *packet;
	int skip = 0;
	Tcl_Obj *result;

	if (objc != 5 && objc != 6) {
		Tcl_WrongNumArgs(interp, 2, objv, "layer field ?skip? packet");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	layer = Tcl_GetStringFromObj(objv[2], NULL);
	field = Tcl_GetStringFromObj(objv[3], NULL);
	if (objc == 6) {
		Tcl_GetIntFromObj(interp, objv[4], &skip);
		packet = Tcl_GetStringFromObj(objv[5], NULL);
	} else {
		packet = Tcl_GetStringFromObj(objv[4], NULL);
	}
	if (ars_d_field_off(packet, layer, field, skip, NULL, NULL, NULL))
		Tcl_SetIntObj(result, 1);
	else
		Tcl_SetIntObj(result, 0);
	return TCL_OK;
}

/* hping setfield layer field value ?skip? packet */
static int HpingSetFieldCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	char *layer, *field, *value, *packet;
	int skip = 0, vstart, vend;
	Tcl_Obj *result;

	if (objc != 6 && objc != 7) {
		Tcl_WrongNumArgs(interp, 2, objv, "layer field value ?skip? packet");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	layer = Tcl_GetStringFromObj(objv[2], NULL);
	field = Tcl_GetStringFromObj(objv[3], NULL);
	value = Tcl_GetStringFromObj(objv[4], NULL);
	if (objc == 7) {
		Tcl_GetIntFromObj(interp, objv[5], &skip);
		packet = Tcl_GetStringFromObj(objv[6], NULL);
	} else {
		packet = Tcl_GetStringFromObj(objv[5], NULL);
	}
	if (!ars_d_field_off(packet, layer, field, skip, NULL, &vstart, &vend)){
		Tcl_AppendStringsToObj(result, "no such field ", layer, " ", field, NULL);
		return TCL_ERROR;
	}
	Tcl_AppendToObj(result, packet, vstart);
	Tcl_AppendObjToObj(result, objv[4]);
	Tcl_AppendStringsToObj(result, packet+vend+1, NULL);
	return TCL_OK;
}

/* hping delfield layer field ?skip? packet */
static int HpingDelFieldCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	char *layer, *field, *packet;
	int skip = 0, fstart, vend;
	Tcl_Obj *result;

	if (objc != 5 && objc != 6) {
		Tcl_WrongNumArgs(interp, 2, objv, "layer field ?skip? packet");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	layer = Tcl_GetStringFromObj(objv[2], NULL);
	field = Tcl_GetStringFromObj(objv[3], NULL);
	if (objc == 6) {
		Tcl_GetIntFromObj(interp, objv[4], &skip);
		packet = Tcl_GetStringFromObj(objv[5], NULL);
	} else {
		packet = Tcl_GetStringFromObj(objv[4], NULL);
	}
	if (!ars_d_field_off(packet, layer, field, skip, &fstart, NULL, &vend)){
		if (objc == 6)
			Tcl_AppendObjToObj(result, objv[5]);
		else
			Tcl_AppendObjToObj(result, objv[4]);
		return TCL_OK;
	}
	if (packet[fstart-1] == ',' &&
	    (packet[vend+1] == ')' || packet[vend+1] == ',')) {
		fstart--;
	}
	Tcl_AppendToObj(result, packet, fstart);
	if (packet[fstart-1] == '(' && packet[vend+1] == ',')
		packet++;
	Tcl_AppendStringsToObj(result, packet+vend+1, NULL);
	return TCL_OK;
}

/* hping checksum string */
static int HpingChecksumCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *result;
	u_int16_t cksum;
	char *data;
	int len;

	result = Tcl_GetObjResult(interp);

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 2, objv, "string");
		return TCL_ERROR;
	}
	data = Tcl_GetStringFromObj(objv[2], &len);
	cksum = ars_cksum(data, len);
	Tcl_SetIntObj(result, cksum);
	return TCL_OK;
}

/* hping setfilter ifname filter */
static int HpingSetFilterCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct recv_handler *ra;
	struct bpf_program bpfp;
	char *ifname, *filter;
	Tcl_Obj *result;

	result = Tcl_GetObjResult(interp);
	if (objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "ifname filter");
		return TCL_ERROR;
	}
	ifname = Tcl_GetStringFromObj(objv[2], NULL);
	filter = Tcl_GetStringFromObj(objv[3], NULL);
	/* Get the interface pcap handler */
	ra = HpingRecvGetHandler(recv_handlers, HPING_IFACE_MAX, ifname, interp);
	if (ra == NULL) {
		Tcl_SetStringObj(result, "Unable to open the interface setting the pcap filter", -1);
		return TCL_ERROR;
	}
	/* Compile and set the filter */
	if (pcap_compile(ra->rh_pcapfp, &bpfp, filter, 0, 0) == -1) {
		Tcl_AppendStringsToObj(result, "Error compiling the pcap filter: '", pcap_geterr(ra->rh_pcapfp), "'", NULL);
		return TCL_ERROR;
	}
	if (pcap_setfilter(ra->rh_pcapfp, &bpfp) == -1) {
		Tcl_AppendStringsToObj(result, "Error setting the pcap filter: '", pcap_geterr(ra->rh_pcapfp), "'", NULL);
		pcap_freecode(&bpfp);
		return TCL_ERROR;
	}
	pcap_freecode(&bpfp);
	return TCL_OK;
}

/* event handler for the [hping event] command. */
void HpingEventHandler(void *clientData, int mask)
{
	struct recv_handler *ra = clientData;

	if (Tcl_EvalObjEx(ra->rh_interp, ra->rh_handlerscript, TCL_EVAL_GLOBAL|TCL_EVAL_DIRECT) != TCL_OK) {
		Tcl_BackgroundError(ra->rh_interp);
	}
}

/* hping event ifname ?script? */
static int HpingEventCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct recv_handler *ra;
	char *ifname;
	Tcl_Obj *result;
	int scriptlen;

	result = Tcl_GetObjResult(interp);
	if (objc != 3 && objc != 4) {
		Tcl_WrongNumArgs(interp, 2, objv, "ifname ?script?");
		return TCL_ERROR;
	}
	ifname = Tcl_GetStringFromObj(objv[2], NULL);
	/* Get the interface pcap handler */
	ra = HpingRecvGetHandler(recv_handlers, HPING_IFACE_MAX, ifname, interp);
	if (ra == NULL) {
		Tcl_SetStringObj(result, "Unable to open the interface setting the pcap filter", -1);
		return TCL_ERROR;
	}
	/* If the script argument is missing, return the script
	 * currently set if any */
	if(objc == 3) {
		if(ra->rh_interp != NULL)
			Tcl_SetObjResult(interp, ra->rh_handlerscript);
		return TCL_OK;
	}
	/* Set the script in the target interface */
	if (ra->rh_interp != NULL)
		Tcl_DecrRefCount(ra->rh_handlerscript);
	/* CHeck if the script is empty, if so clear the handler */
	Tcl_GetStringFromObj(objv[3], &scriptlen);
	if (scriptlen != 0) {
		ra->rh_handlerscript = objv[3];
		Tcl_IncrRefCount(objv[3]);
		ra->rh_interp = interp;
		/* Register the handler for this file descriptor */
		Tcl_CreateFileHandler(pcap_fileno(ra->rh_pcapfp), TCL_READABLE,
				HpingEventHandler, (void*)ra);
	} else {
		ra->rh_interp = NULL;
	}
	return TCL_OK;
}

/* --------------------------------- Misc ----------------------------------- */
#if 0
/* hping setfilter ifname filter */
static int HpingSoftrealtimeCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	struct sched_param sp;
	int min, max, virtual_priority;
	struct Tcl_Obj *result;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 2, objv, "priority (in the range 0-99)");
		return TCL_ERROR;
	}
	result = Tcl_GetObjResult(interp);
	Tcl_GetIntFromObj(interp, objv[2], &virtual_priority);
	if (virtual_priority < 0 || virtual_priority > 99) {
		Tcl_SetStringObj(result, "priority must be in the range 0-99", -1);
		return TCL_ERROR;
	}
	min = sched_get_priority_min(SCHED_RR);
	max = sched_get_priority_max(SCHED_RR);
	/* Map the virutal priority to the range supported in this OS */
	{
		float vmul = (max-min)+1;
		vmul /= 100;
		sp.sched_priority = min + (int)(virtual_priority*vmul);
	}
	/* sched_setscheduler() may fail, but we just ignore the error */
	sched_setscheduler(0, SCHED_RR, &sp);
	return TCL_OK;
}
#endif

/* ---------------------- hping command implementation ---------------------- */
struct subcmd {
	char *name;
	int (*proc)(ClientData cd, Tcl_Interp *i, int, Tcl_Obj *CONST objv[]);
} subcmds[] = {
	{ "resolve", HpingResolveCmd },
	{ "send", HpingSendCmd },
	{ "sendraw", HpingSendRawCmd },
	{ "recv", HpingRecvCmd },
	{ "recvraw", HpingRecvRawCmd },
	{ "setfilter", HpingSetFilterCmd },
	{ "iflist", HpingGetInterfacesCmd },
	{ "outifa", HpingGetOutIfAddrCmd },
	{ "getfield", HpingGetFieldCmd },
	{ "hasfield", HpingHasFieldCmd },
	{ "setfield", HpingSetFieldCmd },
	{ "delfield", HpingDelFieldCmd },
	{ "checksum", HpingChecksumCmd },
	{ "event", HpingEventCmd },
#if 0
	{ "softrealtime", HpingSoftrealtimeCmd },
#endif
	{ NULL, NULL },
};

static int HpingObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	int i = 0;
	char *scmd;
	Tcl_Obj *result;

	if (objc < 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "option ?arg ...?");
		return TCL_ERROR;
	}

	scmd = Tcl_GetStringFromObj(objv[1], NULL);
	while(subcmds[i].name) {
		if (!strcmp(scmd, subcmds[i].name))
			return subcmds[i].proc(clientData, interp, objc, objv);
		i++;
	}
	result = Tcl_GetObjResult(interp);
	Tcl_SetStringObj(result, "Bad option ", -1);
	Tcl_AppendStringsToObj(result, "\"", scmd, "\"", " must be: ", NULL);
	i = 0;
	while(subcmds[i].name) {
		Tcl_AppendStringsToObj(result, subcmds[i].name, NULL);
		if (subcmds[i+1].name)
			Tcl_AppendStringsToObj(result, ", ", NULL);
		i++;
	}
	return TCL_ERROR;
}

/* -------------------- multiprecision math commands ------------------------ */

#if 0
/* XXX: actually this binding is pretty naive, we are not using
 * a Tcl dual-port rappresentation for bignums, instead we convert from/to
 * string rappresentation, wasting the almost decent performences
 * of the sbignum library (and even worse, because to/from string conversion
 * is not optimized). Btw, for now this seems enough, there will be
 * time to improve on this in the future if needed, without to break the API. */

static int BigBasicObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *result;
	mpz_t res, t;
	char *s = NULL, *cmd;

	cmd = Tcl_GetStringFromObj(objv[0], NULL);
	objc--;
	objv++;

	result = Tcl_GetObjResult(interp);
	mpz_init(res);
	mpz_init(t);
	mpz_setzero(res);
	if (cmd[0] == '*' || cmd[0] == '/') {
		if (mpz_set_ui(res, 1) != SBN_OK)
			goto err;
	}
	if ((cmd[0] == '/' || cmd[0] == '%') && objc) {
		s = Tcl_GetStringFromObj(objv[0], NULL);
		if (mpz_set_str(res, s, 0) != SBN_OK)
			goto err;
		objc--;
		objv++;
	}
	while(objc--) {
		s = Tcl_GetStringFromObj(objv[0], NULL);
		if (mpz_set_str(t, s, 0) != SBN_OK)
			goto err;
		switch(cmd[0]) {
		case '+':
			if (mpz_add(res, res, t) != SBN_OK)
				goto err;
			break;
		case '-':
			if (mpz_sub(res, res, t) != SBN_OK)
				goto err;
			break;
		case '*':
			if (mpz_mul(res, res, t) != SBN_OK)
				goto err;
			break;
		case '/':
			if (mpz_tdiv_q(res, res, t) != SBN_OK)
				goto err;
			break;
		case '%':
			if (mpz_mod(res, res, t) != SBN_OK)
				goto err;
			break;
		}
		objv++;
	}
	if ((s = mpz_get_str(NULL, 10, res)) == NULL)
		goto err;
	Tcl_SetStringObj(result, s, -1);
	free(s);
	mpz_clear(res);
	mpz_clear(t);
	return TCL_OK;
err:
	mpz_clear(res);
	mpz_clear(t);
	Tcl_AppendStringsToObj(result, "Not a valid big number: ", s, NULL);
	return TCL_ERROR;
}
#endif

/* -------------------------- Mpz object implementation --------------------- */

static void Tcl_SetMpzObj(Tcl_Obj *objPtr, mpz_ptr val);
//static Tcl_Obj *Tcl_NewMpzObj(void);
static void FreeMpzInternalRep(Tcl_Obj *objPtr);
static void DupMpzInternalRep(Tcl_Obj *srcPtr, Tcl_Obj *copyPtr);
static void UpdateStringOfMpz(Tcl_Obj *objPtr);
static int SetMpzFromAny(struct Tcl_Interp* interp, Tcl_Obj *objPtr);

struct Tcl_ObjType tclMpzType = {
	"mpz",
	FreeMpzInternalRep,
	DupMpzInternalRep,
	UpdateStringOfMpz,
	SetMpzFromAny
};

/* This function set objPtr as an mpz object with value
 * 'val'. If 'val' == NULL, the mpz object is set to zero. */
void Tcl_SetMpzObj(Tcl_Obj *objPtr, mpz_ptr val)
{
	Tcl_ObjType *typePtr;
	mpz_ptr mpzPtr;

	/* It's not a good idea to set a shared object... */
	if (Tcl_IsShared(objPtr)) {
		panic("Tcl_SetMpzObj called with shared object");
	}
	/* Free the old object private data and invalidate the string
	 * representation. */
	typePtr = objPtr->typePtr;
	if ((typePtr != NULL) && (typePtr->freeIntRepProc != NULL)) {
		(*typePtr->freeIntRepProc)(objPtr);
	}
	Tcl_InvalidateStringRep(objPtr);
	/* Allocate and initialize a new bignum */
	mpzPtr = (mpz_ptr) ckalloc(sizeof(struct struct_sbnz));
	mpz_init(mpzPtr);
	if (val && mpz_set(mpzPtr, val) != SBN_OK) {
		panic("Out of memory in Tcl_SetMpzObj");
	}
	/* Set it as object private data, and type */
	objPtr->typePtr = &tclMpzType;
	objPtr->internalRep.otherValuePtr = (void*) mpzPtr;
}

/* Return an mpz from the object. If the object is not of type mpz
 * an attempt to convert it to mpz is done. On failure (the string
 * representation of the object can't be converted on a bignum)
 * an error is returned. */
int Tcl_GetMpzFromObj(struct Tcl_Interp *interp, Tcl_Obj *objPtr, mpz_ptr *mpzPtrPtr)
{
	int result;

	if (objPtr->typePtr != &tclMpzType) {
		result = SetMpzFromAny(interp, objPtr);
		if (result != TCL_OK)
			return result;
	}
	*mpzPtrPtr = (mpz_ptr) objPtr->internalRep.longValue;
	return TCL_OK;
}

/* Create a new mpz object */
Tcl_Obj *Tcl_NewMpzObj(void)
{
	struct Tcl_Obj *objPtr;

	/* Create a new Tcl Object */
	objPtr = Tcl_NewObj();
	Tcl_SetMpzObj(objPtr, 0);
	return objPtr;
}

/* The 'free' method of the object. */
void FreeMpzInternalRep(Tcl_Obj *objPtr)
{
	mpz_ptr mpzPtr = (mpz_ptr) objPtr->internalRep.otherValuePtr;

	mpz_clear(mpzPtr);
	ckfree((void*)mpzPtr);
}

/* The 'dup' method of the object */
void DupMpzInternalRep(Tcl_Obj *srcPtr, Tcl_Obj *copyPtr)
{
	mpz_ptr mpzCopyPtr = (mpz_ptr) ckalloc(sizeof(struct struct_sbnz));
	mpz_ptr mpzSrcPtr;

	mpz_init(mpzCopyPtr);
	mpzSrcPtr = (mpz_ptr) srcPtr->internalRep.otherValuePtr;
	if (mpz_set(mpzCopyPtr, mpzSrcPtr) != SBN_OK)
		panic("Out of memory inside DupMpzInternalRep()");
	copyPtr->internalRep.otherValuePtr = (void*) mpzCopyPtr;
	copyPtr->typePtr = &tclMpzType;
}

/* The 'update string' method of the object */
void UpdateStringOfMpz(Tcl_Obj *objPtr)
{
	size_t len;
	mpz_ptr mpzPtr = (mpz_ptr) objPtr->internalRep.otherValuePtr;

	len = mpz_sizeinbase(mpzPtr, 10)+2;
	objPtr->bytes = ckalloc(len);
	mpz_get_str(objPtr->bytes, 10, mpzPtr);
	/* XXX: fixme, modifing the sbignum library it is
	 * possible to get the length of the written string. */
	objPtr->length = strlen(objPtr->bytes);
}

/* The 'set from any' method of the object */
int SetMpzFromAny(struct Tcl_Interp* interp, Tcl_Obj *objPtr)
{
	char *s;
	mpz_t t;
	mpz_ptr mpzPtr;
	Tcl_ObjType *typePtr;

	if (objPtr->typePtr == &tclMpzType)
		return TCL_OK;

	/* Try to convert */
	s = Tcl_GetStringFromObj(objPtr, NULL);
	mpz_init(t);
	if (mpz_set_str(t, s, 0) != SBN_OK) {
		mpz_clear(t);
		Tcl_ResetResult(interp);
		Tcl_AppendStringsToObj(Tcl_GetObjResult(interp),
				"Invalid big number: \"",
				s, "\" must be a relative integer number",
				NULL);
		return TCL_ERROR;
	}
	/* Allocate */
	mpzPtr = (mpz_ptr) ckalloc(sizeof(struct struct_sbnz));
	mpz_init(mpzPtr);
	/* Free the old object private rep */
	typePtr = objPtr->typePtr;
	if ((typePtr != NULL) && (typePtr->freeIntRepProc != NULL)) {
		(*typePtr->freeIntRepProc)(objPtr);
	}
	/* Set it */
	objPtr->typePtr = &tclMpzType;
	objPtr->internalRep.otherValuePtr = (void*) mpzPtr;
	memcpy(mpzPtr, t, sizeof(*mpzPtr));
	return TCL_OK;
}

/* --------------- the actual commands for multipreicision math ------------- */

static int BigBasicObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *result;
	mpz_t res;
	mpz_ptr t;
	char *cmd;

	cmd = Tcl_GetStringFromObj(objv[0], NULL);
	objc--;
	objv++;

	result = Tcl_GetObjResult(interp);
	mpz_init(res);
	mpz_setzero(res);
	if (cmd[0] == '*' || cmd[0] == '/') {
		if (mpz_set_ui(res, 1) != SBN_OK)
			goto err;
	}
	if ((cmd[0] == '/' || cmd[0] == '%' || cmd[0] == '-') && objc) {
		if (Tcl_GetMpzFromObj(interp, objv[0], &t) != TCL_OK)
			goto err;
		if (mpz_set(res, t) != SBN_OK)
			goto oom;
		if (cmd[0] == '-' && objc == 1)
			res->s = !res->s;
		objc--;
		objv++;
	}
	while(objc--) {
		if (Tcl_GetMpzFromObj(interp, objv[0], &t) != TCL_OK)
			goto err;
		switch(cmd[0]) {
		case '+':
			if (mpz_add(res, res, t) != SBN_OK)
				goto oom;
			break;
		case '-':
			if (mpz_sub(res, res, t) != SBN_OK)
				goto oom;
			break;
		case '*':
			if (mpz_mul(res, res, t) != SBN_OK)
				goto oom;
			break;
		case '/':
			if (mpz_tdiv_q(res, res, t) != SBN_OK)
				goto oom;
			break;
		case '%':
			if (mpz_mod(res, res, t) != SBN_OK)
				goto oom;
			break;
		}
		objv++;
	}
	Tcl_SetMpzObj(result, res);
	mpz_clear(res);
	return TCL_OK;
err:
	mpz_clear(res);
	return TCL_ERROR;
oom:
	Tcl_SetStringObj(result, "Out of memory doing multiprecision math", -1);
	mpz_clear(res);
	return TCL_ERROR;
}

static int BigCmpObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *result;
	mpz_ptr a, b;
	int cmp, res;
	char *cmd;

	if (objc != 3) {
		Tcl_WrongNumArgs(interp, 1, objv, "bignum bignum");
		return TCL_ERROR;
	}

	cmd = Tcl_GetStringFromObj(objv[0], NULL);
	if (Tcl_GetMpzFromObj(interp, objv[1], &a) != TCL_OK ||
	    Tcl_GetMpzFromObj(interp, objv[2], &b) != TCL_OK)
		return TCL_ERROR;
	cmp = mpz_cmp(a, b);

	result = Tcl_GetObjResult(interp);
	res = 0;
	switch(cmd[0]) {
	case '>':
		switch(cmd[1]) {
		case '=':
			if (cmp >= 0) res = 1;
			break;
		default:
			if (cmp > 0) res = 1;
			break;
		}
		break;
	case '<':
		switch(cmd[1]) {
		case '=':
			if (cmp <= 0) res = 1;
			break;
		default:
			if (cmp < 0) res = 1;
			break;
		}
		break;
	case '=':
		if (cmp == 0) res = 1;
		break;
	case '!':
		if (cmp != 0) res = 1;
		break;
	}
	Tcl_SetIntObj(result, res);
	return TCL_OK;
}

static int BigRandObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *result;
	int len = 1;
	mpz_t r;

	if (objc != 1 && objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "?atoms?");
		return TCL_ERROR;
	}
	if (objc == 2 && Tcl_GetIntFromObj(interp, objv[1], &len) != TCL_OK)
		return TCL_ERROR;
	result = Tcl_GetObjResult(interp);
	mpz_init(r);
	if (mpz_random(r, len) != SBN_OK) {
		mpz_clear(r);
		Tcl_SetStringObj(result, "Out of memory", -1);
		return TCL_ERROR;
	}
	Tcl_SetMpzObj(result, r);
	mpz_clear(r);
	return TCL_OK;
}

static int BigSrandObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	char *seed;
	int len;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv, "seed-string");
		return TCL_ERROR;
	}
	seed = Tcl_GetStringFromObj(objv[1], &len);
	sbn_seed(seed, len);
	return TCL_OK;
}

static int BigPowObjCmd(ClientData clientData, Tcl_Interp *interp,
		int objc, Tcl_Obj *CONST objv[])
{
	Tcl_Obj *result;
	int mpzerr;
	mpz_t r; /* result */
	mpz_ptr b, e, m; /* base, exponent, modulo */

	if (objc != 3 && objc != 4) {
		Tcl_WrongNumArgs(interp, 1, objv, "base exponent ?modulo?");
		return TCL_ERROR;
	}
	if (Tcl_GetMpzFromObj(interp, objv[1], &b) != TCL_OK ||
	    Tcl_GetMpzFromObj(interp, objv[2], &e) != TCL_OK ||
	    (objc == 4 && Tcl_GetMpzFromObj(interp, objv[3], &m) != TCL_OK))
		return TCL_ERROR;
	result = Tcl_GetObjResult(interp);
	mpz_init(r);
	if (objc == 4)
		mpzerr = mpz_powm(r, b, e, m);
	else
		mpzerr = mpz_pow(r, b, e);
	if (mpzerr != SBN_OK) {
		mpz_clear(r);
		if (mpzerr == SBN_INVAL)
			Tcl_SetStringObj(result, "Negative exponent", -1);
		else
			Tcl_SetStringObj(result, "Out of memory", -1);
		return TCL_ERROR;
	}
	Tcl_SetMpzObj(result, r);
	mpz_clear(r);
	return TCL_OK;
}

/* ------------------- interpreter creation/invocation ---------------------- */

static int HpingTcl_AppInit(Tcl_Interp *interp)
{
	/* Initialization */
	if (Tcl_Init(interp) == TCL_ERROR)
		return TCL_ERROR;
	HpingRecvInit(recv_handlers, HPING_IFACE_MAX);
	/* Register hping API */
	Tcl_SetVar(interp, "hping_version", RELEASE_VERSION, TCL_GLOBAL_ONLY);
	Tcl_SetVar(interp, "tcl_prompt1", "puts -nonewline {hping3> }", TCL_GLOBAL_ONLY);
	Tcl_CreateObjCommand(interp, "hping", HpingObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "+", BigBasicObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "-", BigBasicObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "*", BigBasicObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "/", BigBasicObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "%", BigBasicObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, ">", BigCmpObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, ">=", BigCmpObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "<", BigCmpObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "<=", BigCmpObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "==", BigCmpObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "!=", BigCmpObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "rand", BigRandObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "srand", BigSrandObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	Tcl_CreateObjCommand(interp, "**", BigPowObjCmd, (ClientData)NULL,
			(Tcl_CmdDeleteProc*)NULL);
	/* Eval the hpingrc, fi any */
	{
		char *home = getenv("HOME");
		if (home) {
			char rcfile[PATH_MAX];
			snprintf(rcfile, PATH_MAX, "%s/.hpingrc", home);
			rcfile[PATH_MAX-1] = '\0';
			Tcl_EvalFile(interp, rcfile);
			Tcl_ResetResult(interp);
		}
	}
	return TCL_OK;
}

void hping_script(int argc, char **argv)
{
	Tcl_Main(argc, argv, HpingTcl_AppInit);
	exit(0);
}

#endif /* USE_TCL */
