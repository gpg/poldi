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

#include <config.h>

#include <stdlib.h>

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

#include "pam-util.h"



/* Used for resetting instances of struct scd_cardinfo.  */
static struct scd_cardinfo cardinfo_null;



/* This functions extracts the raw public key from the certificate
   CERT und returns it as a newly allocated S-Expressions in
   *PUBLIC_KEY.  Returns error code.  */
static gpg_error_t
extract_public_key_from_cert (poldi_ctx_t ctx, ksba_cert_t cert,
			      gcry_sexp_t *public_key)
{
  gcry_sexp_t pubkey;
  gpg_error_t err;
  size_t sexp_len;
  ksba_sexp_t ksba_sexp;

  pubkey = NULL;
  ksba_sexp = NULL;
  err = 0;

  ksba_sexp = ksba_cert_get_public_key (cert);
  sexp_len = gcry_sexp_canon_len (ksba_sexp, 0, NULL, NULL);
  if (!sexp_len)
    {
      log_error ("libksba did not return a proper S-Exp\n");
      err = GPG_ERR_BUG;
      goto out;
    }

  err = gcry_sexp_sscan (&pubkey, NULL, (char *) ksba_sexp, sexp_len);
  if (err)
    {
      log_error ("gcry_sexp_scan failed: %s\n", gpg_strerror (err));
      goto out;
    }

  *public_key = pubkey;

 out:

  ksba_free (ksba_sexp);

  return err;
}

/* This functions checks if RESPONSE/RESPONSE_N contains a valid
   signature for the data CHALLENGE/CHALLENGE_N, created by the
   private key belonging to the certificate CERT.  Returns zero if the
   signature verification succeeded, an error code otherwise. */
static gpg_error_t
verify_challenge_sig (poldi_ctx_t ctx, ksba_cert_t cert,
		      void *challenge, size_t challenge_n,
		      void *response, size_t response_n)
{
  gcry_sexp_t pubkey;
  gpg_error_t err;

  pubkey = NULL;

  err = extract_public_key_from_cert (ctx, cert, &pubkey);
  if (err)
    goto out;

  /* FIXME: probably we need to pass some flags to challenge_verify
     for x509 verification, no? */
  err = challenge_verify (pubkey, challenge, challenge_n,
			  response, response_n);

 out:

  gcry_sexp_release (pubkey);

  return err;
}

/* Extract the certificate contained in the file FILENAME, store it in
   *CERTIFICATE.  Return proper error code.  */
static gpg_error_t
lookup_cert_from_file (poldi_ctx_t ctx, const char *filename, ksba_cert_t *certificate)
{
  gpg_error_t err;
  ksba_cert_t cert;
  void *data;
  size_t datalen;

  cert = NULL;
  data = NULL;
  err = 0;

  err = ksba_cert_new (&cert);
  if (err)
    goto out;

  err = file_to_binstring (filename, &data, &datalen);
  if (err)
    goto out;

  err = ksba_cert_init_from_mem (cert, data, datalen);
  if (err)
    goto out;

  *certificate = cert;

 out:

  if (err)
    ksba_cert_release (cert);
  free (data);

  return err;
}

static gpg_error_t
extract_username_from_cert (ksba_cert_t cert, char **username)
{
  gpg_error_t err;

  /* FIXME: not implemented yet.  */

  *username = xstrdup ("moritz");
  err = 0;

  return err;
}


/* Entry point for the x509 authentication method. Returns TRUE (1) if
   authentication succeeded and FALSE (0) otherwise. */
int
auth_method_x509 (poldi_ctx_t ctx)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gpg_error_t err;
  const char *pam_username;
  char *card_username;
  struct scd_cardinfo cardinfo;
  ksba_cert_t cert;

  cardinfo = cardinfo_null;
  challenge = NULL;
  response = NULL;
  card_username = NULL;
  pam_username = NULL;
  cert = NULL;
  err = 0;

  /*** Connect to Dirmngr. ***/

  err = poldi_dirmngr_connect (ctx, getenv ("DIRMNGR_INFO"), NULL, 0);
  if (err)
    goto out;

  /*** Ask PAM for username. ***/

  err = retrieve_username_from_pam (ctx, &pam_username);
  if (err)
    goto out;

  /*** Receive card info. ***/

  err = poldi_scd_learn (ctx, &cardinfo);
  if (err)
    goto out;

  err = conv_tell (ctx, "[Poldi] connected to card, serial number is: %s",
		   cardinfo.serialno);
  if (err)
    goto out;

  if (ctx->debug)
    {
      err = conv_tell (ctx,
		       "[Poldi] public key url is: %s", cardinfo.pubkey_url);
      if (err)
	goto out;
    }

  /*** Fetch certificate. ***/

  if (! (cardinfo.pubkey_url && ((strncmp (cardinfo.pubkey_url, "ldap://", 7) == 0)
				 || (strncmp (cardinfo.pubkey_url, "file://", 7) == 0))))
    {
      conv_tell (ctx, "[Poldi] `%s' is no valid ldap/file url...", cardinfo.pubkey_url);
      err = GPG_ERR_INV_CARD;
      goto out;
    }

  if (strncmp (cardinfo.pubkey_url, "ldap://", 7) == 0)
    err = poldi_dirmngr_lookup_url (ctx, cardinfo.pubkey_url, &cert);
  else if (strncmp (cardinfo.pubkey_url, "file://", 7) == 0)
    err = lookup_cert_from_file (ctx, cardinfo.pubkey_url + 7, &cert);
  else
    abort ();
  if (err)
    {
      conv_tell (ctx, "[Poldi] failed to look up certificate `%s': %s",
		 cardinfo.pubkey_url, gpg_strerror (err));
      goto out;
    }

  /*** Valide cert. ***/

  /* FIXME: specify issuer? */

  err = poldi_dirmngr_validate (ctx, cert);
  if (err)
    goto out;

  /*** Check username. ***/

  err = extract_username_from_cert (cert, &card_username);
  if (err)
    goto out;

  if (pam_username)
    {
      /* Application wants us to authenticate the user as
	 PAM_USERNAME.  */
      if (strcmp (pam_username, card_username) != 0)
	{
	  /* Current card's cert is not setup for authentication as
	     PAM_USERNAME.  */

	  
	  log_error ("FIXME\n");
	  err = GPG_ERR_INV_USER_ID; /* FIXME, I guess we need a
					better err code. -mo */
	  goto out;
	}
    }

  /*** Generate challenge. ***/

  err = challenge_generate (&challenge, &challenge_n);
  if (err)
    {
      log_error ("Error: failed to generate challenge: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /*** Let card sign the challenge. ***/

  err = poldi_scd_pksign (ctx, "OPENPGP.3",
			  getpin_cb, ctx,
			  challenge, challenge_n,
			  &response, &response_n);
  if (err)
    {
      log_error ("Error: failed to retrieve challenge signature "
		 "from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /*** Verify challenge signature against certificate. ***/

  err = verify_challenge_sig (ctx, cert,
			      challenge, challenge_n,
			      response, response_n);
  if (err)
    {
      log_error ("Error: failed to verify challenge\n");
      goto out;
    }

  if (!pam_username)
    {
      err = send_username_to_pam (ctx, card_username);
      if (err)
	goto out;
    }

  /* Auth succeeded.  */

 out:

  /* Release resources.  */
  poldi_scd_release_cardinfo (&cardinfo);
  ksba_cert_release (cert);
  xfree (card_username);	/* FIXME: which free?  */

  poldi_dirmngr_disconnect (ctx);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  return !err;
}
