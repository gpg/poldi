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

SUBDIRS = libscd
PAM_MODULE_DIRECTORY = "@PAM_MODULE_DIRECTORY@"

generate = \
	sed \
         -e 's,[@]POLDI_CONF_DIRECTORY[@],$(POLDI_CONF_DIRECTORY),g'

BUILT_SOURCES = \
	defs.h

AM_CFLAGS = -Wall -g -fPIC $(LIBGCRYPT_CFLAGS) -I$(top_srcdir)/src/libscd -I$(top_builddir)/src

defs.h: defs.h.in
	$(generate) < $< > $@

noinst_LIBRARIES = libpam_poldi.a
libpam_poldi_a_SOURCES = card.c card.h support.c support.h poldi.c

PAM_POLDI_LIBS = \
	$(LIBGCRYPT_LIBS) $(GPG_ERROR_LIBS) -lc

pam_poldi.so: libpam_poldi.a libscd/libscd.a
	$(LD) --shared -x -u pam_sm_authenticate -u pam_sm_setcred \
	      -o $@ libpam_poldi.a libscd/libscd.a $(PAM_POLDI_LIBS)

all-local: pam_poldi.so

install-pam-module:
	$(INSTALL) pam_poldi.so $(PAM_MODULE_DIRECTORY)

bin_SCRIPTS = poldi-key2sexp

CLEANFILES = \
	$(BUILT_SOURCES) pam_poldi.so

EXTRA_DIST = defs.h.in $(bin_SCRIPTS)
