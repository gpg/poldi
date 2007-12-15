/* sexputil.c - Utility functions for S-expressions.
 * Copyright (C) 2005 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#if 0

/* This file implements a few utility functions useful when working
   with canonical encrypted S-expresions (i.e. not the S-exprssion
   objects from libgcrypt).  */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include "util.h"
#include "sexp-parse.h"

/* Return the so called "keygrip" which is the SHA-1 hash of the
   public key parameters expressed in a way depended on the algorithm.

   KEY is expected to be an canonical encoded S-expression with a
   public or private key. KEYLEN is the length of that buffer.

   GRIP must be at least 20 bytes long On success 0 is return, on
   error an aerror code. */
gpg_error_t
keygrip_from_canon_sexp (const unsigned char *key, size_t keylen,
                         unsigned char *grip)
{
  gpg_error_t err;
  gcry_sexp_t sexp;

  if (!grip)
    return gpg_error (GPG_ERR_INV_VALUE);
  err = gcry_sexp_sscan (&sexp, NULL, (const char *)key, keylen);
  if (err)
    return err;
  if (!gcry_pk_get_keygrip (sexp, grip))
    err = gpg_error (GPG_ERR_INTERNAL);
  gcry_sexp_release (sexp);
  return err;
}


#endif
