# Executable
bin_PROGRAMS = hping3

noinst_LIBRARIES = libars.a

libars_a_SOURCES = ars.c apd.c split.c rapd.c

# Source files
hping3_SOURCES = adbuf.c antigetopt.c apdutils.c arsglue.c \
	binding.c cksum.c datafiller.c datahandler.c display_ipopt.c gethostname.c \
	getifname.c getlhs.c getusec.c hex.c hstring.c if_promisc.c interface.c \
	ip_opt_build.c libpcap_stuff.c listen.c logicmp.c main.c memlock.c \
	memlockall.c memstr.c memunlock.c memunlockall.c opensockraw.c \
	parseoptions.c random.c relid.c resolve.c rtt.c sbignum-tables.c \
	sbignum.c scan.c script.c send.c sendhcmp.c sendicmp.c sendip_handler.c \
	sendip.c sendrawip.c sendtcp.c sendudp.c signal.c sockopt.c \
	statistics.c strlcpy.c usage.c version.c waitpacket.c

# Flags
AM_CFLAGS = @PCAP_CFLAGS@ @TCL_CFLAGS@
hping3_LDADD = libars.a @PCAP_LIBS@ @TCL_LIBS@

.PHONY: depend clean-local install-bin-local

depend:
	@echo "Making dependences..."
	@$(CC) $(AM_CFLAGS) -MM $(hping3_SOURCES) > .depend || true

-include .depend

clean-local:
	rm -rf hping3

BIN_DISTDIR = $(PACKAGE_NAME)-$(PACKAGE_VERSION)

install-bin-local:
	@ABS_DISTDIR=$$(pwd)/../$(BIN_DISTDIR); \
	echo "Installing binary files in $$ABS_DISTDIR..."; \
	$(MAKE) install DESTDIR=$$ABS_DISTDIR;
