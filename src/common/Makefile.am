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

noinst_LIBRARIES = libpoldi-common.a

libpoldi_common_a_SOURCES = \
	card.c card.h support.c support.h options.c options.h

libpoldi_common_a_CFLAGS = \
	-Wall -I$(top_builddir)/src/include \
	-I$(top_srcdir)/src/include -I$(top_srcdir)/src \
	$(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

BUILT_SOURCES = \
	defs.h

generate = \
	sed \
         -e 's,[@]POLDI_CONF_DIRECTORY[@],$(POLDI_CONF_DIRECTORY),g'

defs.h: defs.h.in
	$(generate) < $< > $@

EXTRA_DIST = \
	defs.h.in options.h support.h card.h

CLEANFILES = $(BUILT_SOURCES)
