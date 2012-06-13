You can compile hping3 at least under:

Linux
OpenBSD
FreeBSD
NetBSD
Solaris

But hping3 is beta, for now it was mostly tested only in Linux,
this should change soon now that the first beta is out.

Note that starting from hping3 libpcap should be used
with all the kind of systems, including Linux.

Linux
-----

please, follows this steps:

$ ./configure (first try ./configure --help)
$ vi Makefile (optional)
$ make
$ su
# make install

FreeBSD, OpenBSD, NetBSD
------------------------

You will need the libpcap and the gmake utility installed on your system. 

$ ./configure
$ gmake
$ su (or calife)
# gmake install

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
NOTE: You should take care about your net/bpf.h file installing on
      BSD systems (specially with OpenBSD). If your original bpf.h was
      overwritten with the libpcap one probably hping will not work
      with over some interface.

      For example if you use the libpcap bpf.h on OpenBSD hping will
      not work over PPP interfaces.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Solaris
-------

$ export CC="gcc"
$ ./configure
$ gmake
$ su
# gmake install

ALL
---

To setuid hping3 is like to open the port to script kiddies
for now. Don't do it in any real multiuser and otherwise
security-sensitive system.

antirez
