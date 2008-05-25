/* usersdb.h - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2008 g10 Code GmbH
 
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
 
#ifndef USERSDB_H
#define USERSDB_H

#include <gcrypt.h>

/* This functions figures out wether the provided (SERIALNO, USERNAME)
   pair is contained in the users database.  */
gcry_error_t usersdb_check (const char *serialno, const char *username);

/* This function tries to lookup a username by it's serial number;
   this is only possible in case the specified serial number SERIALNO
   is associated with exactly one username.  The username will be
   stored in newly allocated memory in *USERNAME.  Returns proper
   error code.  */
gcry_error_t usersdb_lookup_by_serialno (const char *serialno, char **username);

/* This function tries to lookup a serial number by it's username;
   this is only possible in case the specified username USERNAME is
   associated with exactly one serial number.  The serial number will
   be stored in newly allocated memory in *SERIALNO.  Returns proper
   error code.  */
gcry_error_t usersdb_lookup_by_username (const char *username, char **serialno);

#endif

/* END */
