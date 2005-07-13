/* card.h - High-Level access to OpenPGP smartcards.
   Copyright (C) 2004, 2005 g10 Code GmbH.
 
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

#ifndef CARD_H
#define CARD_H

#include <gcrypt.h>

gcry_error_t card_open (const char *port, int *slot);
gcry_error_t card_init (int slot, int wait, int require_card_switch);
void card_close (int slot);

gcry_error_t card_info (int slot, const char **serial_no,
			unsigned int *card_version, const char **fingerprint);
gcry_error_t card_read_key (int slot, gcry_sexp_t *key);

gcry_error_t card_pin_provide (int slot, int which, const unsigned char *pin);

gcry_error_t card_sign (int slot, const unsigned char *data, size_t data_n,
			unsigned char **data_signed, size_t *data_signed_n);

#endif
