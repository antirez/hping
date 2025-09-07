AC_PREREQ([2.69])
AC_INIT([hping3], [3.0.0], [antirez@invece.org])
AC_CONFIG_AUX_DIR([build])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])

AC_PROG_CC
AM_PROG_AR
LT_INIT

# Export this info to Makefile
AC_SUBST([PACKAGE_NAME])
AC_SUBST([PACKAGE_VERSION])

# To detect endianess
AC_C_BIGENDIAN([WORDS_BIGENDIAN])

# Detect host system
AC_CANONICAL_HOST

AC_MSG_NOTICE([Checking target operating system...])

case "$host_os" in
  linux*)
    CFLAGS="$CFLAGS -DOSTYPE_LINUX"
    AC_MSG_NOTICE([Detected Linux OS])
    ;;
  darwin*)
    CFLAGS="$CFLAGS -DOSTYPE_DARWIN"
    AC_MSG_NOTICE([Detected macOS])
    ;;
  freebsd*)
    CFLAGS="$CFLAGS -DOSTYPE_FREEBSD"
    AC_MSG_NOTICE([Detected FreeBSD])
    ;;
  netbsd*)
    CFLAGS="$CFLAGS -DOSTYPE_NETBSD"
    AC_MSG_NOTICE([Detected NetBSD])
    ;;
  openbsd*)
    CFLAGS="$CFLAGS -DOSTYPE_OPENBSD"
    AC_MSG_NOTICE([Detected OpenBSD])
    ;;
  mingw* | cygwin* | msys*)
    CFLAGS="$CFLAGS -DOSTYPE_WINDOWS"
    LIBS="$LIBS -lws2_32"
    AC_MSG_NOTICE([Detected Windows (MinGW/Cygwin)])
    ;;
  *)
    AC_MSG_WARN([Unknown OS type: $host_os])
    os_type=UNKNOWN
    ;;
esac

# Add dirs to PKG_CONFIG_PATH
AC_DEFUN([ADD_TO_PKG_CONFIG_PATH],
[
  for dir in $@; do
    if test -d "$dir"; then
      case ":$PKG_CONFIG_PATH:" in
        *":$dir:"*) ;;
        *) PKG_CONFIG_PATH="$dir:$PKG_CONFIG_PATH" ;;
      esac
    fi
  done
  if test -n "$PKG_CONFIG_PATH"; then
    export PKG_CONFIG_PATH
  fi
])

# Detect Homebrew or MSYS2 pkg-config paths
AC_MSG_NOTICE([Detecting pkg-config paths...])
case "$host_os" in
  darwin*)
    case "$host_cpu" in
      x86_64)
        ADD_TO_PKG_CONFIG_PATH([/usr/local/lib/pkgconfig])
        ;;
      aarch64)
        ADD_TO_PKG_CONFIG_PATH([/opt/homebrew/opt/libpcap/lib/pkgconfig])
        ADD_TO_PKG_CONFIG_PATH([/opt/homebrew/opt/tcl-tk/lib/pkgconfig])
        ;;
    esac
    ;;
  mingw* | cygwin* | msys*)
    ADD_TO_PKG_CONFIG_PATH([/mingw64/lib/pkgconfig])
    ;;
esac

# Show PKG_CONFIG_PATH variable
AC_MSG_NOTICE([PKG_CONFIG_PATH=$PKG_CONFIG_PATH])

# Detect dependencies using pkg-config
PKG_CHECK_MODULES([PCAP], [libpcap >= 1.0],
  [AC_MSG_NOTICE([Found libpcap: $PCAP_CFLAGS $PCAP_LIBS])],
  [AC_MSG_ERROR([libpcap >= 1.0 not found. Please, install it.])])

PKG_CHECK_MODULES([TCL], [tcl >= 8.6],
  [AC_MSG_NOTICE([Found Tcl: $TCL_CFLAGS $TCL_LIBS])],
  [AC_MSG_ERROR([Tcl >= 8.6 not found. Please, install it.])])

# Check if Tcl has specific functions
AC_CHECK_LIB([tcl], [Tcl_CreateInterp], [have_tcl=yes], [have_tcl=no])
if test "$have_tcl" = yes; then
  AC_DEFINE([USE_TCL], [1], [Define if Tcl has been found])
  CFLAGS="$CFLAGS -DUSE_TCL"
fi

# Create config.h
AC_CONFIG_HEADERS([config.h])

# Export variables to Makefile
AC_SUBST([PCAP_CFLAGS])
AC_SUBST([PCAP_LIBS])
AC_SUBST([TCL_CFLAGS])
AC_SUBST([TCL_LIBS])
AC_SUBST([LIBS])

# Output final Makefiles
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
