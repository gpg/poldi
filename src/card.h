/* card.h - High-Level access to OpenPGP smartcards.
   Copyright (C) 2004 2003, Free Software Foundation, Inc.
 
   This file is part of Libgcrypt.
  
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef CARD_H
#define CARD_H

#include <gpg-error.h>

gpg_error_t card_open (const char *port, int *slot,
		       unsigned char **serial_no, size_t *serial_no_n);
void card_close (int slot);

gpg_error_t card_info (int slot, unsigned char *key_fpr, unsigned char **login, size_t *login_n);

gpg_error_t card_pin_provide (int slot, unsigned char *pin);

gpg_error_t card_sign (int slot, unsigned char *data, size_t data_n,
		       unsigned char **data_signed, size_t *data_signed_n);

#endif
