/* poldi.c - PAM authentication via OpenPGP smartcards.
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "card.h"
#include "support.h"
#include "options.h"

#define PAM_SUCCESS 0
#define PAM_AUTH_ERR 1

int
main (int argc, char **argv)
{
  unsigned char *username = NULL, key_fpr[41] = {};
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char *challenge = NULL, *response = NULL;
  size_t challenge_n = 0, response_n = 0;
  poldi_key_t key = NULL;
  int slot = -1;
  unsigned char *serialno = NULL;
  size_t serialno_n = 0;
  unsigned char *login = NULL;
  char *pin = NULL;

  if (argc != 2)
    {
      fprintf (stderr, "Usage: %s <username>\n", argv[0]);
      exit (1);
    }
  else
    username = argv[1];

  pin = getpass ("Give me your PIN: ");
  if (! pin)
    exit (1);

  /* Parse options.  */
  err = options_init ();
  if (err)
    goto out;

  /* Open card.  */
  err = card_open (NULL, &slot, &serialno, &serialno_n);
  if (err)
    goto out;

  /* Lookup card information.  */
  err = card_info (slot, key_fpr);
  if (err)
    goto out;

  err = keyid_to_username (key_fpr, &login);
  if (err)
    goto out;
  if (strcmp (username, login))
    /* User identity does not match card login data.  */
    err = GPG_ERR_INTERNAL;
  if (err)
    goto out;

  /* Lookup Key.  */
  err = key_get (&key, key_fpr);
  if (err)
    goto out;

  /* Generate challenge.  */
  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    goto out;

  err = card_pin_provide (slot, pin);
  if (err)
    goto out;

  /* Send challenge to card.  */
  err = card_sign (slot, challenge, challenge_n, &response, &response_n);
  if (err)
    goto out;

  /* Verify response.  */
  err = challenge_verify (key, challenge, challenge_n, response, response_n);
  if (err)
    goto out;

  /* Done.  */

 out:
  if (login)
    free (login);
  if (challenge)
    free (challenge);
  if (key)
    key_destroy (key);

  if (slot != -1)
    card_close (slot);

  return err ? PAM_AUTH_ERR : PAM_SUCCESS;
}
