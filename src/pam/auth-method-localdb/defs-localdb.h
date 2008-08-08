/* defs-localdb.h - Some definitions for the localdb authentication
   Copyright (C) 2008 g10 Code GmbH
 
   This file is part of Poldi.
 
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef INCLUDED_DEFS_LOCALDB_H
#define INCLUDED_DEFS_LOCALDB_H

#include "util/defs.h"

#define POLDI_LOCALDB_DIRECTORY POLDI_CONF_DIRECTORY    "/localdb"

#define POLDI_USERS_DB_FILE     POLDI_LOCALDB_DIRECTORY "/users"
#define POLDI_KEY_DIRECTORY     POLDI_LOCALDB_DIRECTORY "/keys"

#endif
