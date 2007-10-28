# Copyright (C) 2005, 2007 g10 Code GmbH
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

AM_CPPFLAGS =
include $(top_srcdir)/am/cmacros.am

bin_PROGRAMS = poldi-ctrl

poldi_ctrl_SOURCES = poldi-ctrl.c
poldi_ctrl_CFLAGS = \
	-Wall \
	-I$(top_srcdir)/src -I$(top_srcdir)/src/common \
	-I$(top_builddir)/src -I$(top_builddir) \
	$(LIBGCRYPT_CFLAGS) \
	$(GPG_ERROR_CFLAGS)

poldi_ctrl_LDADD = \
	../scd/libscd.a ../common/libpoldi-common.a ../jnlib/libjnlib.a \
	$(LIBGCRYPT_LDFLAGS) \
	$(LIBGCRYPT_LIBS) \
	$(GPG_ERROR_LIBS) \
	$(LIBASSUAN_LIBS)
