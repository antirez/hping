# $smu-mark$ 
# $name: Makefile.in$ 
# $author: Salvatore Sanfilippo 'antirez'$ 
# $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
# $license: This software is under GPL version 2 of license$ 
# $date: Sun Jul 25 17:56:15 MET DST 1999$ 
# $rev: 3$ 

CC= gcc
AR=/usr/bin/ar
RANLIB=/usr/bin/ranlib
CCOPT= -O2 -Wall   -DUSE_TCL
DEBUG= -g
#uncomment the following if you need libpcap based build under linux
#(not raccomanded)
COMPILE_TIME=
INSTALL_MANPATH=/usr/local/man
PCAP=-lpcap

ARSOBJ = ars.o apd.o split.o rapd.o

OBJ=	main.o getifname.o getlhs.o \
	parseoptions.o datafiller.o \
	datahandler.o gethostname.o \
	binding.o getusec.o opensockraw.o \
	logicmp.o waitpacket.o resolve.o \
	sendip.o sendicmp.o sendudp.o \
	sendtcp.o cksum.o statistics.o \
	usage.o version.o antigetopt.o \
	sockopt.o listen.o \
	sendhcmp.o memstr.o rtt.o \
	relid.o sendip_handler.o \
	libpcap_stuff.o memlockall.o memunlockall.o \
	memlock.o memunlock.o ip_opt_build.o \
	display_ipopt.o sendrawip.o signal.o send.o \
	strlcpy.o arsglue.o random.o scan.o \
	hstring.o script.o interface.o \
	adbuf.o hex.o apdutils.o sbignum.o \
	sbignum-tables.o $(ARSOBJ)

all: .depend hping3

dep: .depend
.depend:
	@echo Making dependences
	@$(CC) -MM *.c > .depend

libars.a: $(ARSOBJ)
	$(AR) rc $@ $^
	$(RANLIB) $@

hping3: byteorder.h $(OBJ)
	$(CC) -o hping3 $(CCOPT) $(DEBUG) $(OBJ) -L/usr/local/lib $(PCAP)  -ltcl -lm -lpthread
	@echo
	./hping3 -v
	@echo "use \`make strip' to strip hping3 binary"
	@echo "use \`make install' to install hping3"

hping3-static: byteorder.h $(OBJ)
	$(CC) -static -o hping3-static $(CCOPT) $(DEBUG) $(OBJ) -L/usr/local/lib $(PCAP)  -ltcl -lm -lpthread -ldl

byteorder.h:
	./configure

.c.o:
	$(CC) -c $(CCOPT) $(DEBUG) $(COMPILE_TIME) $<

clean:
	rm -rf hping3 *.o libars.a

distclean:
	rm -rf hping3 *.o byteorder byteorder.h systype.h Makefile libars.a .depend

install: hping3
	cp -f hping3 /usr/sbin/
	chmod 755 /usr/sbin/hping3
	ln -s /usr/sbin/hping3 /usr/sbin/hping
	ln -s /usr/sbin/hping3 /usr/sbin/hping2
	@if [ -d ${INSTALL_MANPATH}/man8 ]; then \
		cp ./docs/hping3.8 ${INSTALL_MANPATH}/man8; \
		chmod 644 ${INSTALL_MANPATH}/man8/hping3.8; \
	else \
		echo "@@@@@@ WARNING @@@@@@"; \
		echo "Can't install the man page: ${INSTALL_MANPATH}/man8 does not exist"; \
	fi

strip: hping3
	@ls -l ./hping3
	strip hping3
	@ls -l ./hping3

include .depend
