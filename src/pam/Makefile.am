# Copyright (C) 2004, 2005, 2007 g10 Code GmbH
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
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src \
	-I$(top_builddir) \
	-I$(top_srcdir)/src/common

include $(top_srcdir)/am/cmacros.am

PAM_MODULE_DIRECTORY = @PAM_MODULE_DIRECTORY@

AM_CFLAGS = \
	-Wall -fPIC \
	 $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)

if AUTH_METHOD_SIMPLEDB
  simpledb = auth-simpledb.c
else
  simpledb =
endif

if AUTH_METHOD_X509
  x509 = auth-x509.c
else
  x509 =
endif

if AUTH_METHOD_TEST
  test = auth-test.c
else
  test =
endif

noinst_LIBRARIES = libpam_poldi.a

libpam_poldi_a_SOURCES = \
 pam_poldi.c conv.c wait-for-card.c getpin-cb.c \
 ${simpledb} ${x509} ${test}

pam_poldi.so: libpam_poldi.a
	$(LD) \
		-u pam_sm_authenticate -u pam_sm_setcred \
		--shared -x -o pam_poldi.so libpam_poldi.a \
		../scd/libscd.a ../common/libpoldi-common.a ../jnlib/libjnlib.a \
		$(LIBGCRYPT_LDFLAGS) $(LIBGCRYPT_LIBS) $(LIBASSUAN_LIBS) -lc

all-local: pam_poldi.so

install-exec-local:
	$(INSTALL) -d $(DESTDIR)$(PAM_MODULE_DIRECTORY)
	$(INSTALL) pam_poldi.so $(DESTDIR)$(PAM_MODULE_DIRECTORY)

uninstall-local:
	rm -f $(DESTDIR)$(PAM_MODULE_DIRECTORY)/pam_poldi.so

CLEANFILES = pam_poldi.so
