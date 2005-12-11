/* usersdb.h - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005 g10 Code GmbH
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

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

/* This function removes entries from the users database.  Either
   USERNAME or SERIALNO must be non-NULL.  If USERNAME is non-NULL and
   serialno is NULL, remove all entries for the given username; if
   USERNAME is NULL and serialno is non-NULL, remove all entries fot
   the specified serial number; if USERNAME and SERIALNO are non-NULL,
   remove exactly this entry.  Returns proper error code.  */
gcry_error_t usersdb_remove (const char *username, const char *serialno);

/* This function adds an entry to the users database; USERNAME and
   SERIALNO must not be NULL.  This is a no-operation in case USERNAME
   is already associated with SERIALNO.  */
gcry_error_t usersdb_add (const char *username, const char *serialno);

/* This functions lists information from the users database to the
   stream STREAM.  Return proper error code.  */
gcry_error_t usersdb_list (FILE *stream);

#endif

/* END */
