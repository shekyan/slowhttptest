#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(slowhttptest, 1.8.1, shekyan@gmail.com)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/slowhttptest.cc])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

LDFLAGS="$LDFLAGS -L/usr/local/opt/openssl/lib"
CPPFLAGS="$CPPFLAGS -I/usr/local/opt/openssl/include"

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for stdc++11, required by auto_ptr and unique_ptr substitution
AX_CXX_COMPILE_STDCXX([11], [noext], [optional])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [SSL_new], [], [
  # Checks for OpenSSL >= 1.1.0
  AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [], [AC_MSG_ERROR([OpenSSL-devel is missing])])
])

# Checks for header files.
AC_HEADER_STDC
AC_DEFINE(USE_COLOR, 1, Use terminal colors)
AC_CHECK_HEADERS([fcntl.h limits.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([atexit gettimeofday poll select socket strerror strstr strtol])

AC_CONFIG_FILES([Makefile src/Makefile man/Makefile])
AC_OUTPUT
