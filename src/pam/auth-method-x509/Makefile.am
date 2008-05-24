# Copyright (C) 2008 g10 Code GmbH
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

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/pam/auth-support \
	-I$(top_srcdir)/src/pam \
	-I$(top_srcdir)/src/scd \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/src/jnlib \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/assuan

include $(top_srcdir)/am/cmacros.am

noinst_LIBRARIES = libpoldi-auth-x509.a

libpoldi_auth_x509_a_SOURCES = \
 auth-x509.c \
 dirmngr.h dirmngr.c


libpoldi_auth_x509_a_CFLAGS = \
	-fPIC -Wall -I$(top_srcdir)/src/pam -I$(top_srcdir)/src \
	$(GPG_ERROR_CFLAGS)
