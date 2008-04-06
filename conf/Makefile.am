# Copyright (C) 2005, 2008 g10 Code GmbH
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

install-conf-skeleton:
	$(INSTALL) -d $(POLDI_CONF_DIRECTORY)/localdb/keys
	install -m 644 -T $(top_srcdir)/conf/README.keys \
	  $(POLDI_CONF_DIRECTORY)/localdb/keys/README
	if test -e $(POLDI_CONF_DIRECTORY)/localdb/users; then \
		echo "$(POLDI_CONF_DIRECTORY)/localdb/users exists, doing nothing here"; \
	else \
		install -m 644 -T $(top_srcdir)/conf/users.skel \
                  $(POLDI_CONF_DIRECTORY)/localdb/users; \
	fi

EXTRA_DIST = users.skel README.keys
