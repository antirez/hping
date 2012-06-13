/* interfaces.c -- that's getifname.c redone with a decent API.
 * This fils is for now used for the TCL bindings but it
 * should replace getifname.c at some time.
 *
 * Note that most of the code comes from getifname.c, so the
 * old copyright still apply:
 *
 * Copyright(C) 1999,2000,2001 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright(C) 2001 by Nicolas Jombart <Nicolas.Jombart@hsc.fr>
 * This code is under the GPL license
 *
 * What changes is the API design that's now sane, the changes
 * are Copyright(C) 2003 Salvatore Sanfilippo.
 */

/* $Id: interface.c,v 1.7 2003/09/08 15:32:40 antirez Exp $ */

#ifdef USE_TCL

#include <stdio.h>		/* perror */
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>		/* struct sockaddr_in */
#include <arpa/inet.h>		/* inet_ntoa */
#include <net/if.h>
#include <unistd.h>		/* close */

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__bsdi__) || defined(__APPLE__)
#include <stdlib.h>
#include <ifaddrs.h>
#include <net/route.h>
#include <net/if_media.h>
#endif /* defined(__*BSD__) */

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) && \
    !defined(__linux__) && !defined(__sun__) && !defined(__bsdi__) && \
    !defined(__APPLE__)
#error Sorry, interface code not implemented.
#endif

#ifdef __sun__
#include <sys/sockio.h>
#include <net/route.h>
#include <net/if_dl.h>
#endif

#include "hping2.h"
#include "globals.h"
#include "interface.h"

/* This function fill the hpingif structures array poited by 'i',
 * able to hold up to 'ilen' elements, with details about
 * all the interfaces present in the system, with the UP flag set.
 *
 * The function returns the number of active interfaces found,
 * regardless to 'ilen'. So if the returned value is > ilen
 * the provided structures array was not enough to hold all
 * the interfaces.
 *
 * On error -1 is returned, and errno set. */
#if (defined OSTYPE_LINUX) || (defined __sun__)
int hping_get_interfaces(struct hpingif *hif, int ilen)
{
	int fd, found = 0, i;
	struct ifconf	ifc;
	struct ifreq ibuf[HPING_IFACE_MAX], ifr;

	/* We need a socket to perform the ioctl()s */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1)
		return -1;
	/* Setup the request structure */
	memset(ibuf, 0, sizeof(struct ifreq)*HPING_IFACE_MAX);
	ifc.ifc_len = sizeof ibuf;
	ifc.ifc_buf = (caddr_t) ibuf;
	/* Get a list of interfaces */
	if (ioctl(fd, SIOCGIFCONF, (char*)&ifc) == -1 ||
		ifc.ifc_len < sizeof(struct ifreq))
	{
		close(fd);
		return -1;
	}
	/* Walk the interfaces list, searching for UP interfaces */
	for (i = 0; i < (ifc.ifc_len/sizeof(struct ifreq)); i++) {
		struct ifreq *this = ibuf+i;
		in_addr_t ifaddr, ifbaddr = 0;
		struct sockaddr_in *sain;
		int ifloopback, ifmtu, ifptp, ifpromisc, ifbroadcast, ifindex, ifnolink = 0;

		memset(&ifr, 0, sizeof(ifr));
		/* It seems we can avoid to call the ioctl against
		 * a bogus device with little efforts */
		if (!this->ifr_name[0])
			continue;
		strlcpy(ifr.ifr_name, this->ifr_name, HPING_IFNAME_LEN);
		/* Get the interface's flags */
		if (ioctl(fd, SIOCGIFFLAGS, (char*)&ifr) == -1) {
			/* oops.. failed, continue with the next */
			continue;
		}
		/* If it's DOWN we are not intersted */
		if (!(ifr.ifr_flags & IFF_UP))
			continue;
		ifloopback = (ifr.ifr_flags & IFF_LOOPBACK) != 0;
		ifptp = (ifr.ifr_flags & IFF_POINTOPOINT) != 0;
		ifpromisc = (ifr.ifr_flags & IFF_PROMISC) != 0;
		ifbroadcast = (ifr.ifr_flags & IFF_BROADCAST) != 0;
#ifdef __sun__
		ifindex = -1;
#else
		/* Get the interface index */
		if (ioctl(fd, SIOCGIFINDEX, (char*)&ifr) == -1) {
			/* oops.. failed, continue with the next */
			continue;
		}
		ifindex = ifr.ifr_ifindex;
#endif
		/* Get the interface address */
		if (ioctl(fd, SIOCGIFADDR, (char*)&ifr) == -1) {
			/* oops.. failed, continue with the next */
			continue;
		}
		sain = (struct sockaddr_in*) &ifr.ifr_addr;
		ifaddr = sain->sin_addr.s_addr;
		/* Get the interface broadcast address */
		if (ifbroadcast) {
			if (ioctl(fd, SIOCGIFBRDADDR, (char*)&ifr) == -1) {
				/* oops.. failed, continue with the next */
				continue;
			}
			sain = (struct sockaddr_in*) &ifr.ifr_broadaddr;
			ifbaddr = sain->sin_addr.s_addr;
		}
		/* Get the interface MTU */
		if (ioctl(fd, SIOCGIFMTU, (char*)&ifr) == -1) {
			/* Failed... we wan't consider it fatal */
			ifmtu = 1500;
		}
		else
		{
#ifdef __sun__
			/* somehow solaris is braidamaged in wrt ifr_mtu */
			ifmtu = ifr.ifr_metric;
#else
			ifmtu = ifr.ifr_mtu;
#endif
		}
#ifdef __linux__
		/* Get the interface link status using MII */
		{
			struct mii_data *mii = (struct mii_data*)&ifr.ifr_data;
			if (ioctl(fd, SIOCGMIIPHY, (char*)&ifr) != -1) {
				int bmsr;

				mii->reg_num = MII_BMSR;
				if (ioctl(fd, SIOCGMIIREG, (char*)&ifr) != -1) {
					bmsr = mii->val_out;
					ifnolink = !(bmsr & MII_BMSR_LINK_VALID);
				}
			}
		}
#endif
		/* Finally populate an hpingif entry if there is room */
		if (!ilen)
			continue;
		strlcpy(hif[found].hif_name, this->ifr_name, HPING_IFNAME_LEN);
		hif[found].hif_mtu = ifmtu;
		hif[found].hif_loopback = ifloopback;
		hif[found].hif_ptp = ifptp;
		hif[found].hif_broadcast = ifbroadcast;
		hif[found].hif_promisc = ifpromisc;
		hif[found].hif_addr[0] = ifaddr;
		hif[found].hif_baddr[0] = ifbaddr;
		hif[found].hif_naddr = 1;
		hif[found].hif_nolink = ifnolink;
		/* if_index should be set to -1 if the OS isn't Linux */
		hif[found].hif_index = ifindex;
		found++;
		ilen--;
	}
	close(fd);
	return found;
}
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
      defined(__bsdi__) || defined(__APPLE__)
/* I wish getifaddrs() API on linux... -- SS */
int hping_get_interfaces(struct hpingif *hif, int ilen)
{
	int found = 0;
	struct ifaddrs *ifap, *ifa;
	struct if_data *ifdata;
	int ifloopback, ifptp, ifpromisc, ifbroadcast, ifnolink;

	/* Get the interfaces list */
	if (getifaddrs(&ifap) == -1)
		return -1;
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		struct ifaddrs *ift;
		struct sockaddr_in *sa, *ba;
		int naddr = 0;
		/* Not interested in DOWN interfaces */
		if (!(ifa->ifa_flags & IFF_UP))
			continue;
		ifloopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
		ifptp = (ifa->ifa_flags & IFF_POINTOPOINT) != 0;
		ifpromisc = (ifa->ifa_flags & IFF_PROMISC) != 0;
		ifbroadcast = (ifa->ifa_flags & IFF_BROADCAST) != 0;
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;
		/* Now search for the AF_INET entry with the same name */
		ift = ifa->ifa_next;
		for (; ift; ift = ift->ifa_next) {
			if (ift->ifa_addr->sa_family == AF_INET &&
			    ift->ifa_addr &&
			    !strcmp(ifa->ifa_name, ift->ifa_name))
			{
				sa = (struct sockaddr_in*) ift->ifa_addr;
				ba = (struct sockaddr_in*) ift->ifa_broadaddr;
				if (naddr < HPING_IFADDR_MAX) {
					hif[found].hif_addr[naddr] =
						sa->sin_addr.s_addr;
					hif[found].hif_baddr[naddr] =
						ba->sin_addr.s_addr;
					naddr++;
				}
			}
		}
		if (!naddr)
			continue;
		/* Read the media status */
		{
			struct ifmediareq ifmr;
			int s = -1;
			memset(&ifmr, 0, sizeof(ifmr));
			strncpy(ifmr.ifm_name, ifa->ifa_name, sizeof(ifmr.ifm_name));
			ifnolink = 0;
			s = socket(AF_INET, SOCK_DGRAM, 0);
			if (s != -1 &&
			    ioctl(s, SIOCGIFMEDIA, (caddr_t)&ifmr) != -1)
			{
				if (ifmr.ifm_status & IFM_AVALID) {
					if (!(ifmr.ifm_status & IFM_ACTIVE))
						ifnolink = 1;
				}
			}
			if (s != -1)
				close(s);
		}
		/* Add the new entry and cotinue */
		ifdata = (struct if_data*) ifa->ifa_data;
		strlcpy(hif[found].hif_name, ifa->ifa_name, HPING_IFNAME_LEN);
		hif[found].hif_broadcast = ifbroadcast;
		hif[found].hif_mtu = ifdata->ifi_mtu;
		hif[found].hif_loopback = ifloopback;
		hif[found].hif_ptp = ifptp;
		hif[found].hif_promisc = ifpromisc;
		hif[found].hif_naddr = naddr;
		hif[found].hif_nolink = ifnolink;
		/* if_index should be set to -1 if the OS isn't Linux */
		hif[found].hif_index = -1;
		found++;
		ilen--;
		if (!ilen)
			break;
	}
	freeifaddrs(ifap);
	return found;
}
#endif /* __*BSD__ */

/* ------------------------------- test main -------------------------------- */
#ifdef TESTMAIN
int main(void)
{
	struct hpingif ifaces[16];
	int found, i, j;

	found = hping_get_interfaces(ifaces, 16);
	printf("Found %d active interfaces:\n", found);
	printf("%-10.10s %-16.16s %-10.10s %-10.10s\n",
			"NAME", "ADDR", "MTU", "INDEX");
	for (i = 0; i < found; i++) {
		struct in_addr ia;
		printf("%-10.10s %-10d %-10d",
				ifaces[i].hif_name,
				ifaces[i].hif_mtu,
				ifaces[i].hif_index);
		printf("(");
		for (j = 0; j < ifaces[i].hif_naddr; j++) {
			ia.s_addr = ifaces[i].hif_addr[j];
			printf("%-16.16s ", inet_ntoa(ia));
		}
		printf(")");
		if (ifaces[i].hif_broadcast) {
			printf("(");
			for (j = 0; j < ifaces[i].hif_naddr; j++) {
				ia.s_addr = ifaces[i].hif_baddr[j];
				printf("%-16.16s ", inet_ntoa(ia));
			}
			printf(")");
		}
		if (ifaces[i].hif_loopback)
			printf(" LOOPBACK");
		if (ifaces[i].hif_ptp)
			printf(" POINTOPOINT");
		if (ifaces[i].hif_promisc)
			printf(" PROMISC");
		if (ifaces[i].hif_broadcast)
			printf(" BROADCAST");
		if (ifaces[i].hif_nolink)
			printf(" NOLINK");
				printf("\n");
	}
	return 0;
}
#endif

#endif /* USE_TCL */
