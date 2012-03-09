#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(slowhttptest, 1.5, shekyan@gmail.com)
AM_INIT_AUTOMAKE([slowhttptest], [1.5])
AC_CONFIG_SRCDIR([src/slowhttptest.cc])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [SSL_library_init], [], [AC_MSG_ERROR([OpenSSL-devel is missing])])

# Checks for header files.
AC_HEADER_STDC
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
