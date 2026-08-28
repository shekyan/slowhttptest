#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.71])
AC_INIT([slowhttptest],[1.10.0],[shekyan@gmail.com])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/slowhttptest.cc])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

# Where is OpenSSL?
#
# macOS ships LibreSSL headers that must not be shadowed, so Homebrew keeps
# OpenSSL keg-only, outside every default search path. This used to be handled
# by hardcoding /usr/local/opt/openssl -- which is the Intel Homebrew prefix.
# Apple Silicon moved it to /opt/homebrew, so on every arm64 Mac ./configure
# failed outright with "OpenSSL-devel is missing", and the fix was undiscoverable
# from that message.
#
# Order matters, and pkg-config is deliberately not first. An arm64 Mac that
# once had Intel Homebrew still has an x86_64 pkg-config under /usr/local
# reporting an x86_64 OpenSSL, which cannot link into an arm64 binary. The brew
# on PATH always belongs to the architecture the shell is running as -- the same
# architecture the compiler targets by default -- so on Darwin it is the
# reliable answer. pkg-config is right everywhere else, including MacPorts and
# every Linux distribution.
AC_ARG_WITH([openssl],
  [AS_HELP_STRING([--with-openssl=DIR],
    [OpenSSL installation prefix (default: ask brew on macOS, else pkg-config)])],
  [openssl_prefix="$withval"], [openssl_prefix=""])

openssl_cflags=""
openssl_ldflags=""
openssl_from="system default paths"

if test -n "$openssl_prefix" && test "x$openssl_prefix" != xyes; then
  openssl_cflags="-I$openssl_prefix/include"
  openssl_ldflags="-L$openssl_prefix/lib"
  openssl_from="--with-openssl=$openssl_prefix"
else
  if test "`uname -s 2>/dev/null`" = Darwin; then
    # A Mac that migrated from Intel keeps both Homebrew prefixes, each holding
    # a different architecture's OpenSSL, and an x86_64 libssl cannot link into
    # an arm64 binary. Order the candidates by what this build actually needs
    # rather than by whichever brew happens to come first on PATH.
    case `uname -m 2>/dev/null` in
      arm64) ssl_roots="/opt/homebrew /usr/local" ;;
      *)     ssl_roots="/usr/local /opt/homebrew" ;;
    esac
    ssl_candidates=""
    for ssl_root in $ssl_roots; do
      for keg in openssl@3 openssl; do
        ssl_candidates="$ssl_candidates $ssl_root/opt/$keg"
      done
    done
    # Then whatever brew reports, which covers a non-standard prefix.
    AC_CHECK_PROG([BREW], [brew], [brew])
    if test -n "$BREW"; then
      for keg in openssl@3 openssl; do
        brew_ssl=`$BREW --prefix $keg 2>/dev/null`
        if test -n "$brew_ssl"; then
          ssl_candidates="$ssl_candidates $brew_ssl"
        fi
      done
    fi
    for ssl_try in $ssl_candidates; do
      if test -d "$ssl_try/include/openssl"; then
        openssl_cflags="-I$ssl_try/include"
        openssl_ldflags="-L$ssl_try/lib"
        openssl_from="$ssl_try"
        break
      fi
    done
  fi
  if test -z "$openssl_cflags"; then
    AC_CHECK_PROG([PKG_CONFIG], [pkg-config], [pkg-config])
    if test -n "$PKG_CONFIG" && $PKG_CONFIG --exists openssl 2>/dev/null; then
      openssl_cflags=`$PKG_CONFIG --cflags openssl`
      openssl_ldflags=`$PKG_CONFIG --libs-only-L openssl`
      openssl_from="pkg-config"
    fi
  fi
fi

AC_MSG_CHECKING([where OpenSSL comes from])
AC_MSG_RESULT([$openssl_from])

CPPFLAGS="$CPPFLAGS $openssl_cflags"
LDFLAGS="$LDFLAGS $openssl_ldflags"

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for stdc++11, required by auto_ptr and unique_ptr substitution
AX_CXX_COMPILE_STDCXX([11], [noext], [optional])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [SSL_new], [], [
  # Checks for OpenSSL >= 1.1.0
  AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [], [AC_MSG_ERROR([
  OpenSSL development files were not found (looked via: $openssl_from).

  Debian/Ubuntu:  apt install libssl-dev
  Fedora/RHEL:    dnf install openssl-devel
  macOS:          brew install openssl@3

  If it is installed somewhere this did not look, say where:
      ./configure --with-openssl=/path/to/openssl])])
])

AC_DEFINE(USE_COLOR, 1, Use terminal colors)
AC_CHECK_HEADERS([fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit gettimeofday poll select socket strerror strstr strtol])

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_OUTPUT
