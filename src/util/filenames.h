/* filenames.h - Functions for dealing with filenames.
   Copyright (C) 1998, 1999, 2000, 2001, 2003,
                 2004, 2005  Free Software Foundation, Inc.
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 
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

#ifndef INCLUDED_FILENAMES_H
#define INCLUDED_FILENAMES_H

#include <poldi.h>

/* Construct a filename from the NULL terminated list of parts,
   including tilde expansion at the beginning. Stores the newly
   allocated string in *PATH, which needs to be freed with xfree().
   Returns error code. This is based on make_filename() as found in
   jnlib. */
gpg_error_t make_filename (char **path, const char *first_part, ...);

#endif
