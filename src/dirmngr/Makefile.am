AM_CPPFLAGS =
include $(top_srcdir)/am/cmacros.am

noinst_LIBRARIES = libdirmngr.a

EXTRA_DIST = README

AM_CFLAGS = \
	-Wall \
	$(GPG_ERROR_CFLAGS) \
	$(LIBASSUAN_CFLAGS) \
	$(LIBKSBA_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

libdirmngr_a_SOURCES = \
 dirmngr.c dirmngr.h \
 fingerprint.c fingerprint.h \
 poldi-dirmngr.c poldi-dirmngr.h
