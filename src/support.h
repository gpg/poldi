/* support.h - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004 g10 Code GmbH
 
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

#ifndef SUPPORT_H
#define SUPPORT_H

#include <gpg-error.h>

typedef struct poldi_key *poldi_key_t;
gpg_error_t challenge_generate (unsigned char **challenge, size_t *challenge_n);
gpg_error_t challenge_verify (poldi_key_t key,
			      unsigned char *challenge, size_t challenge_n,
			      unsigned char *respone, size_t response_n);
gpg_error_t key_get (poldi_key_t *key, unsigned char *key_id);
void key_destroy (poldi_key_t key);

#endif
