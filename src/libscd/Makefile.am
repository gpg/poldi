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

AM_CFLAGS = $(GPG_ERROR_CFLAGS)

noinst_LIBRARIES = libscd.a

libscd_a_SOURCES = \
	apdu.c apdu.h ccid-driver.c ccid-driver.h  \
	iso7816.c iso7816.h tlv.c tlv.h \
	scd.h dynload.h libjnlib-config.h
