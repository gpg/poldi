bin_PROGRAMS = poldi-ctrl

poldi_ctrl_SOURCES = poldi-ctrl.c
poldi_ctrl_CFLAGS = \
	-Wall \
	-I$(top_srcdir)/src -I$(top_builddir)/src -I$(top_builddir) \
	 $(LIBGCRYPT_CFLAGS) $(GPG_ERROR_CFLAGS)
poldi_ctrl_LDADD = \
	../common/libpoldi-common.a ../jnlib/libjnlib.a ../libscd/libscd.a \
	$(LIBGCRYPT_LDFLAGS) $(LIBGCRYPT_LIBS) $(GPG_ERR_LDFLAGS) $(GPG_ERROR_LIBS) \
	$(LIBUSB_LIBS)
