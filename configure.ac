AC_INIT([mod_auth_ofba], [0.6], [manu@netbsd.org])
AC_ARG_WITH(apxs, AC_HELP_STRING([--with-apxs=NAME],
            [name of your apxs executable [[apxs]]]),
            [APXS="$with_apxs"])
AC_PROG_CC
PKG_CHECK_MODULES(APR, apr-1)
PKG_CHECK_MODULES(APRUTIL, apr-util-1)
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE

if test -z "${APXS}"; then
    AC_PATH_PROGS(APXS, apxs2 apxs, no, [$PATH:/usr/sbin:/usr/local/apache2/bin])
fi
if test "$APXS" = no; then
    AC_MSG_ERROR([apxs not found. set apxs with --with-apxs.])
fi
AC_SUBST(APXS)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
