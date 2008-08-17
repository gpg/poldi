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

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/pam \
	-I$(top_srcdir)/src \
	-I$(top_builddir)/src/pam \
	-I$(top_builddir)/src \
	-I$(top_builddir) \
	-I$(top_srcdir)/src/assuan


include $(top_srcdir)/am/cmacros.am

PAM_MODULE_DIRECTORY = @PAM_MODULE_DIRECTORY@

AM_CFLAGS = \
	-fPIC \
	-Wall \
	-I$(top_builddir) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/util \
	$(GPG_ERROR_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

AUTH_METHODS =
AUTH_METHODS_LIBS =

if AUTH_METHOD_LOCALDB
  AUTH_METHODS += auth-method-localdb
  AUTH_METHODS_LIBS += auth-method-localdb/libpoldi-auth-localdb.a
endif

if AUTH_METHOD_X509
  AUTH_METHODS += auth-method-x509
  AUTH_METHODS_LIBS += auth-method-x509/libpoldi-auth-x509.a
endif

SUBDIRS = auth-support $(AUTH_METHODS)

noinst_LIBRARIES = libpam_poldi.a

libpam_poldi_a_SOURCES = \
 pam_poldi.c auth-methods.h

pam_poldi.so: libpam_poldi.a $(AUTH_METHODS_LIBS) auth-support/libpam-poldi-auth-support.a \
		../scd/libscd_shared.a ../util/libpoldi-util_shared.a
	gcc -shared -o pam_poldi.so -Wl,-u,pam_sm_authenticate \
		libpam_poldi.a \
		$(AUTH_METHODS_LIBS) auth-support/libpam-poldi-auth-support.a \
		../scd/libscd_shared.a ../util/libpoldi-util_shared.a ../assuan/libassuan.a \
		$(LIBGCRYPT_LDFLAGS) $(LIBGCRYPT_LIBS) $(KSBA_LIBS)

all-local: pam_poldi.so

install-exec-local:
	$(INSTALL) -d $(DESTDIR)$(PAM_MODULE_DIRECTORY)
	$(INSTALL) pam_poldi.so $(DESTDIR)$(PAM_MODULE_DIRECTORY)

uninstall-local:
	rm -f $(DESTDIR)$(PAM_MODULE_DIRECTORY)/pam_poldi.so

CLEANFILES = pam_poldi.so

# FIXME: LDFLAGS for other libs missing....
