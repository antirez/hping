WARNING: Also try `grep FIXME *.c'

HPING3 TODO.

HPING2 bugs will no longer be handled, the hping2 code inside hping3
is just a compatibility layer that will be dropped once the command
line interface will be reimplemented as an hping script itself.

DONE - split/rapd for IGRP (me)
DONE - add more flags and broadcast address to 'hping iflist'. (me)
DONE - ARS's apd and rapd support for IP and TCP options (me)

- TUN/TAP support -- virtual interface creation, with Tcl channels
- in 'hping recv' a timeout of zero or -1 should be specified using
  keyword like 'dontblock' and 'forever', like a number of packets
  equal to zero should be specified using the 'all' keyword.
- compression primitives 'hping zip', 'hping unzip'.
- recv should support -nobadsum and -notrunc to don't receive packets
  containing layers with the bad checksum or truncated flags set.
- 'hping recvraw' should support a -split option to return the raw data
  splitted in layers in a flat TCL list where elements are:
  {layer0name binary0 layer1name binary1 ...}
- Ability to specify the outgoing interface regardless of the
  destination IP address. (Should be impossible without datalink access)
- 'hping setif ?-promisc? ?-broadcast? ifname'
- 'hping build ?-nocompile? packet' APD->binary
- 'hping describe packet' binary->APD
- IPv6 support in ARS (some still-non-working patch received)
- The hping standard library. that's the real development area
  to make the scripting capabilities useful. The library should
  contain a reasonable number of functions to make it more handy,
  and a number of standard exploits should be rewritten in hping
  as examples. Also support for fragmentation, TCP reassembly,
  and so on will be useful.
- A short way to invoke scripts in 'path' (/usr/local/lib/hping/*.htcl),
  something like: "hping script.htcl". Hping may sense it's an .htlc
  file and not a strange-locking domain name ;) and perform a lookup
  in the standard library of scripts (~/.hping/*.htcl for example).
- Convert all the raw-socket stuff (used in output) to datalink.
- Implement a scanner, with random nmap and hping features, and also:
	FIN scan follwed by a SYN scan, this can be useful
	since many admins limit the incoming SYN packets, so the
	SYN or connect() scan is too slow, while the FIN scan
	show filtered ports as open. We can do a FIN scan, then scan
	the ports that appears to be open with SYN. Should
	be both fast and accurate.

TODO (about TCL scripting, but for future releases)

- 'hping iflist' should include the link header length (or -1 if it's unknown)
- 'hping recv' and 'recvraw' should have a -layer2 option to return the whole
  level 2 frame. The same for 'hping send' and 'hping sendraw'.
- 'hping guesslhs' should run the ipv4 header detection and return the lhs
