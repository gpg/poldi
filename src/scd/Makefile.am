AM_CPPFLAGS =
include $(top_srcdir)/am/cmacros.am

noinst_LIBRARIES = libscd.a

EXTRA_DIST = README

AM_CFLAGS = \
	-Wall \
	$(GPG_ERROR_CFLAGS) \
	$(LIBASSUAN_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common

libscd_a_SOURCES = \
 scd.c scd.h \
 poldi-scd.c poldi-scd.h
