dnl -*- Autoconf -*-

AC_INIT([guile-aws], [0.1.0])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([color-tests -Wall -Wno-portability foreign])
AM_SILENT_RULES([yes])

AC_PATH_PROG([GUILE], [guile])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([pre-inst-env], [chmod +x pre-inst-env])

GUILE_PKG([3.0 2.2])
GUILE_PROGS
GUILE_MODULE_REQUIRED(json)

AC_OUTPUT
