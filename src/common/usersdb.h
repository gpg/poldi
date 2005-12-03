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

gcry_error_t usersdb_lookup_by_serialno (const char *serialno, char **username);

gcry_error_t usersdb_lookup_by_username (const char *username, char **serialno);

gcry_error_t usersdb_remove (const char *username, const char *serialno);

gcry_error_t usersdb_add (const char *username, const char *serialno);

gcry_error_t usersdb_list (FILE *stream);

#endif

/* END */
