/* auth-x509.c - x509 authentication backend for Poldi.
 * Copyright (C) 2007 g10 Code GmbH
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>

// FIXME, define required?
#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include <gpg-error.h>
#include <gcrypt.h>
#include <stdio.h>		/* FIXME, so far only required for
				   ksba.h. */
#include <ksba.h>

#include "poldi-ctx.h"

#include "scd/poldi-scd.h"
#include "dirmngr/poldi-dirmngr.h"
#include "common/usersdb.h"
#include "common/util.h"
#include "common/support.h"
#include "getpin-cb.h"
#include "wait-for-card.h"
#include "conv.h"

static struct scd_cardinfo cardinfo_null;

int
auth_method_x509 (poldi_ctx_t ctx)
{
  gpg_error_t err;
  const void *username_void;
  const char *username;
  int ret;
  struct scd_cardinfo cardinfo;
  ksba_cert_t cert;

  cardinfo = cardinfo_null;
  username = NULL;
  cert = NULL;

  /*** Connect to Dirmngr. ***/

  err = poldi_dirmngr_connect (ctx);
  if (err)
    goto out;

  /*** Ask PAM for username. ***/

  ret = pam_get_item (ctx->pam_handle, PAM_USER, &username_void);
  if (ret != PAM_SUCCESS)
    {
      err = gpg_error (GPG_ERR_INTERNAL);
      goto out;
    }
  username = username_void;

  /*
   * Receive card info.
   */

  err = poldi_scd_learn (ctx, &cardinfo);
  if (err)
    goto out;

  conv_tell (ctx,
	     "SERIALNO: %s\n"
	     "PUBKEY-URL: %s\n",
	     cardinfo.serialno, cardinfo.pubkey_url);

  /*** Fetch certificate. ***/

  if ((!cardinfo.pubkey_url) || (strncmp (cardinfo.pubkey_url, "ldap://", 7) != 0))
    {
      conv_tell (ctx, "`%s' is no valid ldap url...\n", cardinfo.pubkey_url);
      err = GPG_ERR_GENERAL;	/* FIXME!! NO_CERT or something? */
      goto out;
    }

  conv_tell (ctx, "Looking up `%s' through dirmngr...\n", cardinfo.pubkey_url);

  err = poldi_dirmngr_lookup_url (ctx, cardinfo.pubkey_url, &cert);
  if (err)
    {
      conv_tell (ctx, "failed! dirmngr said: %s\n", gpg_strerror (err));
      goto out;
    }

  conv_tell (ctx, "FIXME: authentication not implemented yet\n");
  err = GPG_ERR_NOT_IMPLEMENTED;

 out:

  /* Release resources.  */
  poldi_scd_release_cardinfo (&cardinfo);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  return !err;
}
