AM_CPPFLAGS =
include $(top_srcdir)/am/cmacros.am

noinst_LIBRARIES = libscd.a libscd_shared.a

EXTRA_DIST = README

scd_CFLAGS = \
	-Wall \
	$(GPG_ERROR_CFLAGS) \
	$(LIBASSUAN_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util

scd_SOURCES = scd.c scd.h

libscd_a_SOURCES = $(scd_SOURCES)
libscd_a_CFLAGS = $(scd_CFLAGS)
libscd_shared_a_SOURCES = $(scd_SOURCES)
libscd_shared_a_CFLAGS = -fPIC $(scd_CFLAGS)
