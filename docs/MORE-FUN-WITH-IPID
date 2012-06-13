Posted to bugtraq mailing list (20 Nov 1999):

---
Hi,

some little new ideas about IP ID issue:

The first is about linux firewalling: since it increase IP ID global counter
even if an outgoing packet will be filtered we are able, for example, to
scan UDP ports even if ICMP type 3 output is DENY, and in general it is possibleto know when TCP/IP stack reply a packet even if the reply is dropped.
I think (but not tested) that this is true for almost all firewalls.

The second issue concern the ability to uncover firewall rules. For example
it is travial to know if host A filter packets from the IP X.Y.Z.W monitoring
IP ID incresing of host A or host with X.Y.Z.W address (this changes if we are
interested to know input or output rules) and sending packets that suppose
some reply. Also this is related with the ability to scan the ports of hosts
that drop all packets with a source different than host.trusted.com.
There are others stuff like this but they are only different faces of the
same concepts.

Some people thinks that this kind of attacks isn't a "real world" attacks,
I'm strongly interested to know what's bugtraq readers opinion (IMO this
kind of attacks are feasible and usefull for an attacker. For exaple the
ability to scan the ports with only spoofed packets and the ability to
guess remote hosts traffic are a lot real).

ciao,
antirez
