# Copyright (C) 2004, 2005 g10 Code GmbH
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

PAM_MODULE_DIRECTORY = @PAM_MODULE_DIRECTORY@

AM_CFLAGS = \
	-Wall -fPIC \
	-I$(top_srcdir)/src -I$(top_builddir)/src -I$(top_builddir) \
	-I$(top_srcdir)/src/common \
	 $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

pam_poldi.o: pam_poldi.c
	$(CC) $(AM_CFLAGS) $(CFLAGS) -c -o pam_poldi.o $(top_srcdir)/src/pam/pam_poldi.c

pam_poldi.so: pam_poldi.o ../common/libpoldi-common.a ../jnlib/libjnlib.a \
	      ../libscd/libscd.a
	$(LD) --shared -x \
	      -o $@ pam_poldi.o \
	      ../common/libpoldi-common.a ../jnlib/libjnlib.a \
	     ../libscd/libscd.a $(LIBGCRYPT_LDFLAGS) $(LIBGCRYPT_LIBS) $(LIBUSB_LIBS) -lc

all-local: pam_poldi.so

install-exec-local:
	$(INSTALL) -d $(DESTDIR)$(PAM_MODULE_DIRECTORY)
	$(INSTALL) pam_poldi.so $(DESTDIR)$(PAM_MODULE_DIRECTORY)

uninstall-local:
	rm -f $(DESTDIR)$(PAM_MODULE_DIRECTORY)/pam_poldi.so

EXTRA_DIST = pam_poldi.c

CLEANFILES = pam_poldi.o pam_poldi.so
