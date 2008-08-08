dnl macros to configure gnupg
dnl Copyright (C) 1998, 1999, 2000, 2001, 2003 Free Software Foundation, Inc.
dnl
dnl This file is part of GnuPG.
dnl
dnl GnuPG is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl 
dnl GnuPG is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA


dnl GNUPG_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN([GNUPG_CHECK_TYPEDEF],
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(gnupg_cv_typedef_$1,
    [AC_TRY_COMPILE([#define _GNU_SOURCE 1
    #include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], gnupg_cv_typedef_$1=yes, gnupg_cv_typedef_$1=no )])
    AC_MSG_RESULT($gnupg_cv_typedef_$1)
    if test "$gnupg_cv_typedef_$1" = yes; then
        AC_DEFINE($2,1,[Defined if a `]$1[' is typedef'd])
    fi
  ])

dnl GNUPG_CHECK_ENDIAN
dnl define either LITTLE_ENDIAN_HOST or BIG_ENDIAN_HOST
dnl
define(GNUPG_CHECK_ENDIAN,
  [
    tmp_assumed_endian=big
    if test "$cross_compiling" = yes; then
      case "$host_cpu" in
         i@<:@345678@:>@* )
            tmp_assumed_endian=little
            ;;
         *)
            ;;
      esac
      AC_MSG_WARN(cross compiling; assuming $tmp_assumed_endian endianess)
    fi
    AC_MSG_CHECKING(endianess)
    AC_CACHE_VAL(gnupg_cv_c_endian,
      [ gnupg_cv_c_endian=unknown
        # See if sys/param.h defines the BYTE_ORDER macro.
        AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/param.h>], [
        #if !BYTE_ORDER || !BIG_ENDIAN || !LITTLE_ENDIAN
         bogus endian macros
        #endif], [# It does; now see whether it defined to BIG_ENDIAN or not.
        AC_TRY_COMPILE([#include <sys/types.h>
        #include <sys/param.h>], [
        #if BYTE_ORDER != BIG_ENDIAN
         not big endian
        #endif], gnupg_cv_c_endian=big, gnupg_cv_c_endian=little)])
        if test "$gnupg_cv_c_endian" = unknown; then
            AC_TRY_RUN([main () {
              /* Are we little or big endian?  From Harbison&Steele.  */
              union
              {
                long l;
                char c[sizeof (long)];
              } u;
              u.l = 1;
              exit (u.c[sizeof (long) - 1] == 1);
              }],
              gnupg_cv_c_endian=little,
              gnupg_cv_c_endian=big,
              gnupg_cv_c_endian=$tmp_assumed_endian
            )
        fi
      ])
    AC_MSG_RESULT([$gnupg_cv_c_endian])
    if test "$gnupg_cv_c_endian" = little; then
      AC_DEFINE(LITTLE_ENDIAN_HOST,1,
                [Defined if the host has little endian byte ordering])
    else
      AC_DEFINE(BIG_ENDIAN_HOST,1,
                [Defined if the host has big endian byte ordering])
    fi
  ])

# GNUPG_BUILD_PROGRAM(NAME,DEFAULT)
# Add a --enable-NAME option to configure an set the
# shell variable build_NAME either to "yes" or "no".  DEFAULT must
# either be "yes" or "no" and decided on the default value for
# build_NAME and whether --enable-NAME or --disable-NAME is shown with 
# ./configure --help
AC_DEFUN([POLDI_ENABLE_FEATURE],
  [$1=$2
   m4_if([$2],[yes],[
      AC_ARG_ENABLE([$3], AC_HELP_STRING([--disable-$3],
                                         [disable $4]),
                           $1=$enableval, $1=$2)
    ],[
      AC_ARG_ENABLE([$3], AC_HELP_STRING([--enable-$3],
                                         [enable $4]),
                           $1=$enableval, $1=$2)
    ])
   case "$$1" in
         no|yes)
           ;;
         *)
	   echo "$1"
           AC_MSG_ERROR([argument for --enable-$3 must be either yes or no])
           ;;
   esac
  ])
