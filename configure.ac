# -*- Autoconf -*-
AC_INIT([hping3], [3.0.0], [antirez@invece.org])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])


# Tools
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AR
LT_INIT

# ----------- libpcap support -----------

AC_ARG_WITH([libpcap],
  [AS_HELP_STRING([--with-libpcap=PATH], [Specify root path to libpcap (contains include/ and lib/)])],
  [libpcap_path="$withval"],
  [libpcap_path=""]
)

AS_IF([test -z "$libpcap_path"], [
  AC_MSG_ERROR([--with-libpcap=PATH is required when compiling.])
])

AC_MSG_NOTICE([Checking for libpcap...])
pcap_inc_dir="$libpcap_path/include"
pcap_lib_dir="$libpcap_path/lib"
pcap_static="$pcap_lib_dir/libpcap.a"

CPPFLAGS="$CPPFLAGS -I$pcap_inc_dir"
LDFLAGS="$LDFLAGS -L$pcap_lib_dir"

AS_IF([test "x$enable_static" = "xyes" && test -f "$pcap_static"], [
  AC_MSG_NOTICE([Using static libpcap from $pcap_lib_dir])
  LIBS="$pcap_static -ldl"
], [
  AC_CHECK_LIB([pcap], [pcap_open_live], [], [
    AC_MSG_ERROR([libpcap not found in $libpcap_path])
  ])
])

# ----------- Tcl scripting support -----------

AC_ARG_ENABLE([tcl],
  [AS_HELP_STRING([--disable-tcl], [Disable Tcl scripting support])],
  [],
  [enable_tcl=yes]
)

AC_ARG_WITH([libtcl],
  [AS_HELP_STRING([--with-libtcl=PATH], [Specify root path to Tcl (contains include/ and lib/)])],
  [libtcl_path="$withval"],
  [libtcl_path=""]
)

AS_IF([test "x$enable_tcl" = "xyes"], [
  AS_IF([test -z "$libtcl_path"], [
    AC_MSG_ERROR([--with-libtcl=PATH is required when Tcl scripting is enabled and compiling.])
  ])
])

tcl_inc_dir="$libtcl_path/include"
tcl_lib_dir="$libtcl_path/lib"
CPPFLAGS="$CPPFLAGS -I$tcl_inc_dir"
LDFLAGS="$LDFLAGS -L$tcl_lib_dir"

AS_IF([test "x$enable_tcl" = "xyes"], [
  AC_MSG_NOTICE([Checking for Tcl (8.0–8.6)...])
  have_tcl_lib=no
  have_tcl_hdr=no
  TCL_VERSIONS="8.6 8.5 8.4 8.3 8.2 8.1 8.0"

  if test "x$enable_static" = "xyes"; then
    for ver in $TCL_VERSIONS; do
      tcl_static="$tcl_lib_dir/libtcl${ver}.a"
      if test -f "$tcl_static"; then
        have_tcl_lib=yes
        TCL_LIBS="$tcl_static -lm -lpthread"
        TCL_VERSION_DETECTED="$ver"
        break
      fi
    done
  fi

  if test "x$have_tcl_lib" = "xno"; then
    for ver in $TCL_VERSIONS; do
      AC_CHECK_LIB([tcl$ver], [Tcl_Init], [
        have_tcl_lib=yes
        TCL_LIBS="-ltcl$ver -lm -lpthread"
        TCL_VERSION_DETECTED="$ver"
        break
      ])
    done
  fi

  AC_CHECK_HEADER([tcl.h], [have_tcl_hdr=yes], [
    AC_MSG_WARN([tcl.h not found; Tcl scripting disabled])
  ])

  AS_IF([test "x$have_tcl_lib" = "xyes" -a "x$have_tcl_hdr" = "xyes"], [
    AC_DEFINE([USE_TCL], [1], [Define if using Tcl scripting])
    USE_TCL_CPPFLAGS="-DUSE_TCL"
  ], [
    enable_tcl=no
    TCL_LIBS=""
    USE_TCL_CPPFLAGS=""
    TCL_VERSION_DETECTED=""
  ])
])

AC_SUBST([TCL_LIBS])
AC_SUBST([USE_TCL_CPPFLAGS])
AC_SUBST([TCL_VERSION_DETECTED])






# Endianness
# Endianness
AC_C_BIGENDIAN(
  [AC_DEFINE([__BIG_ENDIAN_BITFIELD], [1], [Define if target is big endian])],
  [AC_DEFINE([__LITTLE_ENDIAN_BITFIELD], [1], [Define if target is little endian])]
)

# OS type macros
case "$host_os" in
  linux*)   AC_DEFINE([OSTYPE_LINUX], [1], [Define if OS is Linux]) ;;
  solaris*) AC_DEFINE([OSTYPE_SUNOS], [1], [Define if OS is Solaris])
            SOLARISLIB="-lsocket -lresolv -lnsl"
            AC_DEFINE([STUPID_SOLARIS_CHECKSUM_BUG], [1], [Define if workaround needed for Solaris checksum bug]) ;;
  freebsd*) AC_DEFINE([OSTYPE_FREEBSD], [1], [Define if OS is FreeBSD]) ;;
  openbsd*) AC_DEFINE([OSTYPE_OPENBSD], [1], [Define if OS is OpenBSD]) ;;
  netbsd*)  AC_DEFINE([OSTYPE_NETBSD], [1], [Define if OS is NetBSD]) ;;
  darwin*)  AC_DEFINE([OSTYPE_DARWIN], [1], [Define if OS is Darwin/macOS]) ;;
  cygwin*)  AC_DEFINE([OSTYPE_CYGWIN], [1], [Define if OS is Cygwin]) ;;
  *)        AC_DEFINE([OSTYPE_UNKNOWN], [1], [Define if OS is unknown]) ;;
esac
AC_SUBST([SOLARISLIB])

# Output summary
AC_MSG_NOTICE([])
AC_MSG_NOTICE([------ Configuration Summary ------])
AC_MSG_NOTICE([OS             : ${host_os}])
AC_MSG_NOTICE([libpcap        : yes])
AC_MSG_NOTICE([Tcl support    : ${enable_tcl}])
AC_MSG_NOTICE([Tcl version    : ${TCL_VERSION_DETECTED}])
AC_MSG_NOTICE([Static build   : ${enable_static:-no}])
AC_MSG_NOTICE([Cross-compiler : ${host}])
AC_MSG_NOTICE([------------------------------------])
AC_MSG_NOTICE([Run 'make' to build hping3])
AC_MSG_NOTICE([])
AC_OUTPUT

