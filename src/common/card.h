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

/* List key types.  */
typedef enum
  {
    CARD_KEY_NONE,
    CARD_KEY_SIG,
    CARD_KEY_ENC,
    CARD_KEY_AUTH
  }
card_key_t;

/* This functions opens the card terminal specified by PORT.  On
   success an according handle, the slot ID, will be stored in *SLOT.
   Returns proper error code.  */
gcry_error_t card_open (const char *port, int *slot);

/* This functions initializes a card, which is to be inserted in the
   slot SLOT; initializing it means selecting the OpenPGP application.

   Depending on the boolean value WAIT, do not fail in case there is
   no card in SLOT but wait until a card becomes available; do not
   wait more then TIMEOUT seconds or wait forever in case TIMEOUT is
   zero.

   Depending on the boolean value REQUIRE_CARD_SWITCH, require that a
   card, which is already inserted at the time of this function call,
   needs to be reinserted.

   Returns proper error code.  */
gcry_error_t card_init (int slot, int wait, unsigned int timeout,
			int require_card_switch);

/* This function releases the slot handle specified by SLOT.  */
void card_close (int slot);

/* This function retrieves basic information from the card, which is
   to be accessed through SLOT and which needs to be initialized.

   If SERIAL_NO is not NULL, retrieve the card's serial number and
   store it in a newly allocated C string, which is to be stored in
   *SERIAL_NO.

   If CARD_VERSION is not NULL, store the card's version number in
   *CARD_VERSION.

   If FINGERPRINT is not NULL, retrieve the signing key's fingerprint
   and store it in newly allocated C string, which is to be stored in
   *FINGERPRINT.

   Returns proper error code.  */
gcry_error_t card_info (int slot, char **serial_no,
			unsigned int *card_version,
			card_key_t type, char **fingerprint);

/* This function retrieves the key identified by TYPE of an
   initialized card accessed through SLOT and stores it, converted
   into an S-Expression, in *KEY.  Returns proper error code.  */
gcry_error_t card_read_key (int slot, card_key_t type,
			    gcry_sexp_t *key, unsigned int *nbits);

/* This function sends the PIN contained in PIN to the card accessed
   through SLOT.  WHICH specifies the type of PIN:

   WHICH=1: CHV1
   WHICH=2: CHV2
   WHICH=3: CHV3.

   Returns proper error code.  */
gcry_error_t card_pin_provide (int slot, int which, const unsigned char *pin);

#if 0

/* This function requests the card accessed through SLOT to sign the
   data in DATA of DATA_N bytes; the signature is to be stored in
   *DATA_SIGNED, it's length in bytes in *DATA_SIGNED_N.  Returns
   proper error code.  */
gcry_error_t card_sign (int slot, const unsigned char *data, size_t data_n,
			unsigned char **data_signed, size_t *data_signed_n);

/* This functions requests the card acccessed trough SLOT to decrypt
   the data in DATA of DATA_N bytes; the decrypted data is to be
   stored in *DATA_DECRYPTED, it's length in bytes in
   *DATA_DECRYPTED_N.  Returns proper error code.  */
gcry_error_t card_decrypt (int slot, const unsigned char *data, size_t data_n,
			   unsigned char **data_decrypted,
			   size_t *data_decrypted_n);

#endif

/* This function requests the card accessed through SLOT to sign the
   data in DATA of DATA_N bytes with the authentication key; the
   signature is to be stored in DATA_SIGNED, it's length in bytes in
   *DATA_SIGNED_N.  Returns proper error code.  */
gcry_error_t card_auth (int slot, const unsigned char *data, size_t data_n,
			unsigned char **data_signed, size_t *data_signed_n);

#endif

/* END */
