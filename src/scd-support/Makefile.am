AM_CPPFLAGS =
include $(top_srcdir)/am/cmacros.am

noinst_LIBRARIES = libscd-support.a

EXTRA_DIST = README

AM_CFLAGS = \
	-Wall \
	$(GPG_ERROR_CFLAGS) \
	$(LIBASSUAN_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	-I$(top_builddir)/src \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/common \
	-I$(top_srcdir)/src/scd

libscd_support_a_SOURCES = \
	wait-for-card.c getpin-callback.c \
	scd-support.h
