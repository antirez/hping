# Makefile.am for hping3

# Specify the program to build
bin_PROGRAMS = hping3

# Define CFLAGS, CPPFLAGS, and LDFLAGS
# AM_CPPFLAGS is for preprocessor flags (includes, defines)
# AM_CFLAGS is for compiler flags
# AM_LDFLAGS is for linker flags
AM_CFLAGS = -O3 -Wall $(DEBUG) # DEBUG variable is not defined anywhere, usually handled by configure.ac --enable-debug
AM_CPPFLAGS = $(USE_TCL_CPPFLAGS)
AM_LDFLAGS =
ACLOCAL_AMFLAGS= -I m4


# Source files for hping3
hping3_SOURCES = \
	main.c getifname.c getlhs.c \
	parseoptions.c datafiller.c \
	datahandler.c gethostname.c \
	binding.c getusec.c opensockraw.c \
	logicmp.c waitpacket.c resolve.c \
	sendip.c sendicmp.c sendudp.c \
	sendtcp.c cksum.c statistics.c \
	usage.c version.c antigetopt.c \
	sockopt.c listen.c \
	sendhcmp.c memstr.c rtt.c \
	relid.c sendip_handler.c \
	libpcap_stuff.c memlockall.c memunlockall.c \
	memlock.c memunlock.c ip_opt_build.c \
	display_ipopt.c sendrawip.c signal.c send.c \
	strlcpy.c arsglue.c random.c scan.c \
	hstring.c script.c interface.c \
	adbuf.c hex.c apdutils.c sbignum.c \
	sbignum-tables.c \
	ars.c apd.c split.c rapd.c

# Linker libraries
# hping3_LDADD will include LIBS (from AC_CHECK_LIB), SOLARISLIB, and TCL_LIB
# Libtool handles adding -static or -dynamic based on configure options
hping3_LDADD = $(LIBS) $(SOLARISLIB) $(TCL_LIBS)

# Man page installation
man8_MANS = docs/hping3.8
# Extra distributions (these are files that are part of the distribution
# but not built by Automake itself)
EXTRA_DIST = \
    configure.ac \
    Makefile.am \
    docs/hping3.8


distclean-local:
	rm -f configure aclocal.m4 Makefile.in config.h.in  config.h.in~ autoreconf.log
	rm -f config.guess config.sub ltmain.sh missing install-sh depcomp configure~ compile
	rm -rf autom4te.cache m4



# Special target to make a purely static hping3 (if desired, though `configure --enable-static` should handle this)
# This is typically not needed if LT_INIT is used and configure --enable-static is passed.
# However, if you wanted a separate `make hping3-static` rule, it'd look something like this:
# (Note: This might conflict with Libtool's default behavior, usually configure --enable-static is enough)
# hping3-static: $(hping3_OBJECTS)
# 	$(LIBTOOL) --tag=CC --mode=link $(CC) $(AM_CFLAGS) $(hping3_OBJECTS) -static -o $@ $(hping3_LDADD)

# Clean rules are handled by Automake
# distclean is also handled by Automake

# include .depend is no longer needed, Automake handles dependencies

