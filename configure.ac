# configure.ac - for the GSCUTILSGnuPG 1.9
# Copyright (C) 2004 g10 Code GmbH
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
AC_INIT(poldi, 0.2-cvs1, gnupg-devel@gnupg.org)

PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

NEED_LIBGCRYPT_VERSION=0
NEED_GPG_ERROR_VERSION=0.7
	
AC_CONFIG_SRCDIR(src/pam/pam_poldi.c)
AM_CONFIG_HEADER(config.h)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

POLDI_CONF_DIRECTORY="${sysconfdir}/poldi"
AC_SUBST(POLDI_CONF_DIRECTORY)

PAM_MODULE_DIRECTORY="/lib/security"
AC_SUBST(PAM_MODULE_DIRECTORY)

AC_GNU_SOURCE

# Some status variables to give feedback at the end of a configure run
#have_gpg_error=no
#have_libgcrypt=no 

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])
AC_DEFINE_UNQUOTED(PACKAGE_BUGREPORT, "$PACKAGE_BUGREPORT",
                                        [Bug report address])

AH_BOTTOM([
/* Tell the sources taken from GnuPG's SCD what header file they
   should use. */
#define GNUPG_SCD_MAIN_HEADER "scd.h"
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
AC_PROG_CPP
AC_PROG_RANLIB
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_SYS_LARGEFILE

#
# Checks for libraries.
#

have_libgcrypt=no
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_VERSION",
                  have_libgcrypt=yes,have_libgcrypt=no)

have_gpg_error=no
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)


#
# libusb allows us to use the integrated CCID smartcard reader driver.
#
LIBUSB_LIBS=""
AC_CHECK_LIB(usb, usb_bulk_write,
             [ LIBUSB_LIBS="$LIBUSB_LIBS -lusb"
               AC_DEFINE(HAVE_LIBUSB,1,
               [defined if libusb is available])
             ])
AC_SUBST(LIBUSB_LIBS)
AC_CHECK_FUNCS(usb_get_busses memicmp stpcpy strlwr strtoul memmove stricmp)

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T

# Necessary for libscd.
GNUPG_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
GNUPG_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
GNUPG_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)

AC_CHECK_SIZEOF(unsigned short)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long)

 
# Checks for library functions.

#
# See whether we have dlopen available, so that PC/SC can be loaded on
# demand.
#
_dl_save_libs=$LIBS
LIBS=""
AC_SEARCH_LIBS(dlopen,dl,found_dlopen=yes)
if test x"$found_dlopen" = "xyes" ; then
   AC_DEFINE(HAVE_DL_DLOPEN,1,
             [Defined when the dlopen function family is available])
   DLLIBS=$LIBS
else
   DLLIBS=""
   LIBS=$_dl_save_libs
fi
AC_SUBST(DLLIBS)

AM_CONDITIONAL(CROSS_COMPILING, test x$cross_compiling = xyes)

if test "$GCC" = yes; then
    if test "$USE_MAINTAINER_MODE" = "yes"; then
        CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
        CFLAGS="$CFLAGS -Wformat-nonliteral"
    else
        CFLAGS="$CFLAGS -Wall"
    fi
fi

# We use jnlib, so tell other modules about it
AC_DEFINE(HAVE_JNLIB_LOGGING, 1,
         [Defined if jnlib style logging fucntions are available])

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
if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi

AC_CONFIG_FILES([Makefile
		 doc/Makefile
		 src/Makefile
		 src/jnlib/Makefile
		 src/libscd/Makefile
		 src/common/Makefile
		 src/pam/Makefile
		 src/ctrl/Makefile])
AC_OUTPUT
