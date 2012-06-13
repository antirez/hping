/* Copyright (C) 2003 Salvatore Sanfilippo <antirez@invece.org>
 * $Id: apdutils.c,v 1.2 2003/09/01 00:22:06 antirez Exp $
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* This function returns the indexes to seek a given field
 * of a given layer in an APD packet rappresentation.
 * The function is quite fast compared to a pure-Tcl regexp
 * based approach, sorry if it is quite ugly.
 *
 * field_start, value_start and value_end are set by reference,
 * the following graph shows where this three indexes point,
 * assuming the function is called with layer="ip" and field="tos":
 *
 * ip(ihl=5,ver=4,tos=0x10,...)+udp(...)
 *                ^   ^  ^
 *                |   |  |____ field_start
 *                |   |_______ value_start
 *                |___________ value_end
 *
 * The function returns 0 if layer/field don't match with
 * the packet, otherwise 1 is returned. If a given index pointer
 * is NULL, it is just not used. */
int ars_d_firstfield_off(char *packet, char *layer, char *field,
		int *field_start, int *value_start, int *value_end)
{
	int layerlen = strlen(layer);
	int fieldlen = strlen(field);
	int pktlen = strlen(packet);
	char *x = alloca(layerlen+3);
	char *y = alloca(fieldlen+3);
	char *p, *j, *w;
	x[0] = '+';
	memcpy(x+1, layer, layerlen);
	x[layerlen+1] = '(';
	x[layerlen+2] = '\0';
	if (pktlen <= layerlen+1)
		return 0;
	if (memcmp(packet, x+1, layerlen+1) == 0) {
		p = packet;
	} else {
		p = strstr(packet, x);
		if (p == NULL)
			return 0;
		p++;
	}
	y[0] = ',';
	memcpy(y+1, field, fieldlen);
	y[fieldlen+1] = '=';
	y[fieldlen+2] = '\0';
	p += layerlen + 1;
	pktlen -= p-packet;
	if (pktlen <= fieldlen+1)
		return 0;
	if ((j = strchr(p, ')')) == NULL)
		return 0;
	if (memcmp(p, y+1, fieldlen+1)) {
		p = strstr(p, y);
		if (p == NULL || p >= j)
			return 0;
		p++;
	}
	if (field_start) *field_start = p-packet;
	p += fieldlen + 1;
	if (value_start) *value_start = p-packet;
	w = strchr(p, ',');
	if (w && w < j)
		j = w;
	if (value_end) *value_end = (j-packet)-1;
	return 1;
}

/* This function extends ars_d_firstfield_off(), allowing to specify
 * how much layers of the same type of 'layer' to skip. This is
 * useful to get fields in packets where the same layer is present
 * more then one time. For example ICMP error packets contains
 * a quoted IP packet that can be accessed using a skip value of 1
 * (to skip the first IP layer). */
int ars_d_field_off(char *packet, char *layer, char *field, int skip,
		int *field_start, int *value_start, int *value_end)
{
	char *p = packet;
	int end, toadd;

	/* Minimal overhead with a zero skip */
	if (skip <= 0)
		return ars_d_firstfield_off(packet, layer, field,
				field_start, value_start, value_end);
	do {
		if (!ars_d_firstfield_off(p, layer, field,
					field_start, value_start, &end))
			return 0;
		toadd = p-packet;
		p += end;
	} while(skip--);
	if (value_end) *value_end = end + toadd;
	if (field_start) *field_start += toadd;
	if (value_start) *value_start += toadd;
	return 1;
}

/* The function calls ars_d_field_off() in order to
 * return a dynamically allocated string containing
 * the value of the given field. On error (no match or out of mem)
 * NULL is returned. */
char *ars_d_field_get(char *packet, char *layer, char *field, int skip)
{
	int start, end, len;
	char *x;

	if (!ars_d_field_off(packet, layer, field, skip, NULL, &start, &end))
		return NULL;
	len = end-start+1;
	if ((x = malloc(len+1)) == NULL)
		return NULL;
	memcpy(x, packet+start, len);
	x[len] = '\0';
	return x;
}

#ifdef TESTMAIN
char packet[] = "ip(ihl=5,ver=4,tos=00,totlen=1340,id=43581,fragoff=0,mf=0,df=1,rf=0,ttl=4,proto=6,cksum=9029,saddr=192.168.1.6,daddr=195.14.221.49)+tcp(sport=55617,dport=80,seq=4048054653,ack=1246471424,x2=0,off=5,flags=pa,win=8576,cksum=6082,urp=0)+data(hex=0cd68e94650059b4dc81b1562d7288254c3faf5d651b75d1393abc6dcd5f5d1ad2f56b9bca9edc84b9212890b9407232b0d0e10222b4391e2e915c8ba4c0cb89c540d4c1389503c2d48b2c60a6c73500603cdba72144eccbd8f4cfc020af7d540fe99ea8fd0975371fb8f8167a0a1b94cf53e208cdce36dc2b692a857b958822ddac8d2cd1e8d9966a0361f345988084d558d8679f1393de4781ac8499178059f9f01d940cb2a8dfc288e500637c6a424ebde14068523291dc92bcec2e5eb4c8c53ad4192ff1e41e9e9e7cd5e389ef9dd3b9062d8509ac2f88a41863f009dfb3b08c041a68369561fa2bd9ffc09289d8719c2d52d6a687f3b837bbc51eb2a3aac50fafd2abf1a8374ca8cf6ab76a8a562e7e0995b43508a8a39abc6760738e4ef532b8968ef460719c2070eaa38fb67325e4f0903fe407b203a2d3d1bfb78dc0c430fbfc20029b0a2445801f9478beee2d964d95241edfa6322f34515b39ebbf2de43a3c533ba870ea8ef78b3baa70fb1d3491dcf931459395e92497205b633af5f426a921b79a28c5e1b86558f7b7e608c3cb0afa15dc8c60ad1897944074c712e141ae9ed44f3431c9e51ab6f92ab8248cc24279db669f6da1fecdf9ea299b24d94e7847545eab663e77e3a23fe133a8c7d18d23efbfa0a236586c315455ecae03c1d2e23bf713e9a240b26b83c5e5ead196581805ac6132f1454fb4c91a16d9cada46b1be728d697167d9b3c29cdcea3b04346116457bba715203bd45a3540d57a71368e9a015ae8d36368176752fdd93e975fd18e2797f53408aba273a20bad8f7f7763c20954e4aa371e0bbd4c03a9963a175fdd06457b3e39732e65d9443959adc1555e4bd59dcb7855bf204e31f04ad8ffb956e04a10896fdf861bd42408e10f47d38cffb3c9719bcff739265e3591bf5a2beedd9c90dc8a72c2dee5dc896914dee4c48f43c977736e4112255e4cd10d7812693b99f4484aa70d632f7ae94ce0bda674df8775fd017e40baae817de058b4563cba5539c5d4d580a754a3a042e49a6e56c7ce889388a606fde17ee8e25fa1c30abdd924564a3c03e5d2b7f265f4d030060b5d24da79c32a518c3febc3d8c2386298bfebbaee444be0252ac5ec5c93a212d4ebc0dd8e227629eb28161bb9037e6df3c02191a4a7b7c0c4187c99b99801399dbf325fcff261a97638c39656f32d292c3527004f7c00d1b51131d5d997a6a9934885ca44b4d856bddcb12b80f9484b3a5885e0c79e63ec1374efece0f7140df35c949dcaa49af4165d754dd1ff6d7747864ebfe1aac0d3979923e2cffc0ea2da693b10c2c794957161f382811d0196d69ab9b3b8c5edc8338f17632470f50ec34ceaecf4c6e30e6131db340a51f7113b614993f22b582bb47f8caffd8bca5aff325443a55fe16f2f57d8cdf86cd131062672b48122bdaabd844abf20ccfd8d82069c2120e706a4894709758fcd35c6e57a6fb64d6c03d14ef4ac5ba6347cc92b6d899cd6cdbf9e8be573eff7550dbb453cb5ac1fa9900ce73cd57cdc3b95aaad0d293a9c7e4a5054f8a46c9052d44f0d4b3fc5f6670a9c318f44d429f35ca4c1ce1b6d39daf02fa05c8decc46889a6fcf0f4491e563cbde158dc046f52cd328ac40c9c26629f6f42de60f9c7d52fe131a16b04a37c4967794ee4aa76c28463e8ca393abd6ca7aa41a9155db94a7d14f7a5f6ebaa2ee6751f0b139b403d524f433c939c382001fc1c6e9be709b55fcf01b01996889529917fabae23310a54878ca94601cf3182e9a5b01eabb588ff953c91205c56b54a2e125aa9c1c9753e5515566d027a827e55e1a6863cc82)+ip(ihl=5,ver=4,tos=10,totlen=1340,id=43581,fragoff=0,mf=0,df=1,rf=0,ttl=4,proto=6,cksum=9029,saddr=192.168.1.6,daddr=195.14.221.49)+tcp(sport=55617,dport=80,seq=4048054653,ack=1246471424,x2=0,off=5,flags=pa,win=8576,cksum=6082,urp=0)+ip(ihl=5,ver=4,tos=20,totlen=1340,id=43581,fragoff=0,mf=0,df=1,rf=0,ttl=4,proto=6,cksum=9029,saddr=192.168.1.6,daddr=195.14.221.49)";

int main(int argc, char **argv)
{
	int i = 10000;
	int field_start, value_start, value_end;
	int skip;

	if (argc != 4)
		exit(1);
	skip = atoi(argv[3]);
	if (ars_d_field_off(packet, argv[1], argv[2], skip,
			&field_start, &value_start, &value_end))
	{
		int j;
		printf("|");
		for (j = field_start; j <= value_end; j++) {
			printf("%c", packet[j]);
		}
		printf("|\n");
	}
	while(i--) {
		ars_d_field_off(packet, argv[1], argv[2], skip,
				NULL, NULL, NULL);
	}
	return 0;
}
#endif
