# Copyright (C) 2004, 2007, 2008, 2009 g10 Code GmbH
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

noinst_LIBRARIES = libpoldi-util.a libpoldi-util_shared.a

poldi_util_SOURCES = \
	util-local.h \
	support.c support.h \
	membuf.c membuf.h \
	util.h \
	convert.c \
	simplelog.c simplelog.h \
	simpleparse.c simpleparse.h \
	filenames.c filenames.h

poldi_util_CFLAGS = \
	-Wall \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	 $(GPG_ERROR_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

BUILT_SOURCES = \
	defs.h

libpoldi_util_a_CFLAGS = $(poldi_util_CFLAGS)
libpoldi_util_shared_a_CFLAGS = -fPIC $(poldi_util_CFLAGS)
libpoldi_util_a_SOURCES = $(poldi_util_SOURCES)
libpoldi_util_shared_a_SOURCES = $(poldi_util_SOURCES)

generate = \
	sed \
         -e 's,[@]POLDI_CONF_DIRECTORY[@],$(POLDI_CONF_DIRECTORY),g'

defs.h: defs.h.in configure-stamp
	$(generate) < $< > $@

EXTRA_DIST = \
	defs.h.in configure-stamp.in

CLEANFILES = $(BUILT_SOURCES) configure-stamp
