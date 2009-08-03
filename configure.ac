# configure.ac - Configure script for Poldi
# Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
# 
# This file is part of Poldi.
#
# Poldi is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# Poldi is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA

# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.52)
min_automake_version="1.7.9"

# Version number: Remember to change it immediately *after* a release.
#                 Add a "-cvs" prefix for non-released code.
AC_INIT(poldi, 0.4.2-cvs, gnupg-devel@gnupg.org)

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

NEED_LIBGCRYPT_VERSION=0
NEED_GPG_ERROR_VERSION=0.7

NEED_KSBA_API=1
NEED_KSBA_VERSION=1.0.2

	
AC_CONFIG_SRCDIR(src/pam/pam_poldi.c)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

POLDI_CONF_DIRECTORY="${sysconfdir}/poldi"
AC_SUBST(POLDI_CONF_DIRECTORY)

# Implementation of the --with-pam-module-directory switch.
DEFAULT_PAM_MODULE_DIRECTORY="${libdir}/security"
AC_ARG_WITH(pam-module-directory,
	    [  --with-pam-module-directory=NAME
                          Use NAME as installation directory for PAM modules ],
	    PAM_MODULE_DIRECTORY="$withval",
	    PAM_MODULE_DIRECTORY="$DEFAULT_PAM_MODULE_DIRECTORY")
AC_SUBST(PAM_MODULE_DIRECTORY)

AC_GNU_SOURCE

have_gpg_error=no
have_libgcrypt=no 
have_ksba=no

POLDI_ENABLE_FEATURE(enable_auth_x509, yes, x509-auth, support for X509 authentication)
POLDI_ENABLE_FEATURE(enable_auth_localdb, yes, localdb-auth, support for local-db authentication)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",
                                        [Bug report address])
AC_DEFINE_UNQUOTED(NEED_LIBGCRYPT_VERSION, "$NEED_LIBGCRYPT_VERSION",
                                       [Required version of Libgcrypt])
AC_DEFINE_UNQUOTED(NEED_KSBA_VERSION, "$NEED_KSBA_VERSION",
                                       [Required version of Libksba])


AH_BOTTOM([
/* Setup the hardwired names of modules. */
#ifndef GNUPG_DEFAULT_SCD
#define GNUPG_DEFAULT_SCD    ( GNUPG_BINDIR "/scdaemon" )
#endif
#ifndef GNUPG_DEFAULT_DIRMNGR
#define GNUPG_DEFAULT_DIRMNGR    ( GNUPG_BINDIR "/dirmngr" )
#endif
])

AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_MAKE_SET
AM_SANITY_CHECK
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_SYS_LARGEFILE

#
# Checks for libraries.
#

AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_VERSION",
                  have_libgcrypt=yes,have_libgcrypt=no)
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)
AM_PATH_KSBA("$NEED_KSBA_API:$NEED_KSBA_VERSION",have_ksba=yes,have_ksba=no)

AC_CHECK_FUNCS(stpcpy strtoul)
AC_CHECK_FUNCS(fopencookie funopen nanosleep)

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)

# Checks for library functions.

# FIXME: what is this for?? -moritz
AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

if test "$GCC" = yes; then
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wformat-nonliteral"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

#
# Taken from libassuan source package
#

AC_CHECK_HEADERS([string.h locale.h sys/uio.h])
AC_TYPE_SIGNAL
#AC_DEFINE(USE_DESCRIPTOR_PASSING, 0, [We do not need this feature])
AC_REPLACE_FUNCS(setenv)
# Check for funopen
AC_CHECK_FUNCS(funopen)
if test $ac_cv_func_funopen != yes; then
    # No funopen but we can implement that in terms of fopencookie.
    AC_CHECK_FUNCS(fopencookie)
    if test $ac_cv_func_fopencookie = yes; then
        AC_LIBOBJ([funopen])
    else
        AC_MSG_WARN([
***
*** No implementation of fopencookie or funopen available.
*** The assuan_get_data_fp feature won't work.
***])
    fi
fi

# Native language support:
AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION(0.17)

#
# Decide what to build
#

if test $have_ksba = no; then
  enable_auth_x509=no
fi
AM_CONDITIONAL(AUTH_METHOD_X509, test "$enable_auth_x509" = "yes")
AM_CONDITIONAL(AUTH_METHOD_LOCALDB, test "$enable_auth_localdb" = "yes")

if test "$enable_auth_x509" = "yes"; then
   AC_DEFINE(ENABLE_AUTH_METHOD_X509, 1, [Enable X509 authentication method])
fi
if test "$enable_auth_localdb" = "yes"; then
   AC_DEFINE(ENABLE_AUTH_METHOD_LOCALDB, 1, [Enable local-db authentication method])
fi

#
# Print errors here so that they are visible all
# together and the user can acquire them all together.
#
die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgpg-error to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/alpha/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libgcrypt" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgcrypt to build this program.
*** This library is for example available at
***   ftp://ftp.gnupg.org/gcrypt/libgcrypt
*** (at least version $NEED_LIBGCRYPT_VERSION is required.)
***]])
fi
if test "$have_ksba" = "no"; then
   AC_MSG_NOTICE([[
***
*** libksba not found, building without X.509 authentication support.
*** libksba can be retrieved from:
***   ftp://ftp.gnupg.org/gcrypt/libksba/
*** (at least version $NEED_KSBA_VERSION (API $NEED_KSBA_API) is required).
***]])
fi
if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi

AC_CONFIG_FILES([Makefile
		 po/Makefile.in
		 m4/Makefile
		 am/Makefile
		 src/Makefile
		 src/assuan/Makefile
		 src/util/Makefile
		 src/scd/Makefile
		 src/ctrl/Makefile
		 src/pam/Makefile
		 src/pam/auth-support/Makefile
		 src/pam/auth-method-localdb/Makefile
		 src/pam/auth-method-x509/Makefile
		 doc/Makefile
		 tests/Makefile
		 tools/Makefile
		 conf/Makefile])
AC_OUTPUT

if test "$PAM_MODULE_DIRECTORY" = "$DEFAULT_PAM_MODULE_DIRECTORY"; then
   AC_MSG_WARN([
**
** Warning: using default value ($DEFAULT_PAM_MODULE_DIRECTORY) as
**          installation directory for PAM module; this is probably not
**          what you want. Either use the configure flag
**
**                      --with-pam-module-directory=DIRECTORY
**
**          or copy the newly built pam_poldi.so into the correct directory
**          manually. Usually PAM modules are located in /lib/security.
**])
else
  AC_MSG_NOTICE([PAM module installation directory: $PAM_MODULE_DIRECTORY])
fi

echo "
        Poldi v${VERSION} has been configured as follows:

        installation directory for PAM module: $PAM_MODULE_DIRECTORY
	configuration directory:               $POLDI_CONF_DIRECTORY
        
             X509 authentication: $enable_auth_x509
         local-db authentication: $enable_auth_localdb

"
