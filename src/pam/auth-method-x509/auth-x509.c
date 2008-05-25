/* auth-x509.c - x509 authentication backend for Poldi.
 * Copyright (C) 2007, 2008 g10 Code GmbH
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
#include <stdio.h>		/* FIXME, so far only required for
				   ksba.h. */
#include <gpg-error.h>
#include <gcrypt.h>
#include <ksba.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "scd/scd.h"
#include "dirmngr.h"
#include "conv.h"
#include "util/util.h"
#include "util/support.h"
#include "auth-support/ctx.h"
#include "auth-support/getpin-cb.h"
#include "auth-support/pam-util.h"
#include "auth-methods.h"
#include "util/defs.h"



struct x509_ctx_s
{
  char *x509_domain;
  char *dirmngr_socket;
};

typedef struct x509_ctx_s *x509_ctx_t;

static gpg_error_t
auth_method_x509_init (void **opaque)
{
  x509_ctx_t cookie;
  gpg_error_t err;

  cookie = malloc (sizeof (*cookie));
  if (!cookie)
    err = gpg_error_from_errno (errno);
  else
    {
      cookie->x509_domain = NULL;
      cookie->dirmngr_socket = NULL;
      err = 0;
    }

  *opaque = cookie;

  return err;
}

static void
auth_method_x509_deinit (void *opaque)
{
  x509_ctx_t cookie = opaque;

  if (cookie)
    {
      free (cookie->x509_domain);
      free (cookie->dirmngr_socket);
      free (opaque);
    }
}

/* Option IDs.  */
enum arg_opt_ids
  {
    arg_dirmngr_socket = 500,
    arg_x509_domain,
  };

/* Option specifications. */
static ARGPARSE_OPTS x509_arg_opts[] =
  {
    { arg_dirmngr_socket,
      "dirmngr-socket", 2, "|FILENAME|Specify local socket for dirmngr access" },
    { arg_x509_domain,
      "x509-domain", 2, "|NAME|Specify X509 domain" },
    { 0 }
  };

/* Implements support for the "x509-domain" option.  */
static gpg_error_t
auth_method_x509_parsecb (ARGPARSE_ARGS *parg, void *cookie)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  x509_ctx_t ctx = cookie;

  switch (parg->r_opt)
    {
    case arg_x509_domain:
      ctx->x509_domain = strdup (parg->r.ret_str);
      if (!ctx->x509_domain)
	{
	  log_error ("failed to duplicate string (x509-domain option) (length: %i): %s\n",
		     strlen (parg->r.ret_str), strerror (errno));
	  break;
	}
      break;

    case arg_dirmngr_socket:
      ctx->dirmngr_socket = strdup (parg->r.ret_str);
      if (!ctx->dirmngr_socket)
	{
	  log_error ("failed to duplicate string (dirmngr-socket option) (length: %i): %s\n",
		     strlen (parg->r.ret_str), strerror (errno));
	  break;
	}
      break;

    default:
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      break;
    }

  return gpg_error (err);
}



/* This functions extracts the raw public key from the certificate
   CERT und returns it as a newly allocated S-Expressions in
   *PUBLIC_KEY.  Returns error code.  */
static gpg_error_t
extract_public_key_from_cert (poldi_ctx_t ctx, ksba_cert_t cert, gcry_sexp_t *public_key)
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

  err = challenge_verify (pubkey, challenge, challenge_n,
			  response, response_n);

 out:

  gcry_sexp_release (pubkey);

  return err;
}

/* Extract the certificate contained in the file FILENAME, store it in
   *CERTIFICATE.  Return proper error code.  */
static gpg_error_t
lookup_cert_from_file (const char *filename, ksba_cert_t *certificate)
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

/* Return an allocated string with the email address extracted from a
   DN */
static char *
email_kludge (const char *name)
{
  const char *p, *string;
  unsigned char *buf;
  int n;

  string = name;
  for (;;)
    {
      p = strstr (string, "1.2.840.113549.1.9.1=#");
      if (!p)
        return NULL;
      if (p == name || (p > string+1 && p[-1] == ',' && p[-2] != '\\'))
        {
          name = p + 22;
          break;
        }
      string = p + 22;
    }


  /* This looks pretty much like an email address in the subject's DN
     we use this to add an additional user ID entry.  This way,
     openSSL generated keys get a nicer and usable listing */
  for (n=0, p=name; hexdigitp (p) && hexdigitp (p+1); p +=2, n++)
    ;
  if (!n)
    return NULL;
  buf = malloc (n+3);
  if (!buf)
    return NULL; /* oops, out of core */
  *buf = '<';
  for (n=1, p=name; hexdigitp (p); p +=2, n++)
    buf[n] = xtoi_2 (p);
  buf[n++] = '>';
  buf[n] = 0;
  return (char*)buf;
}

/* Returns true if the mail address (of the form "<user@domain>")
   contained in SUBJECT has X509_DOMAIN as it's domain part.  */
static int
email_address_match (const char *subject, const char *x509_domain)
{
  size_t subject_len = strlen (subject);
  size_t x509_domain_len = strlen (x509_domain);

  /* FIXME: some more sanity checks necessary?  */

  if ((x509_domain_len < subject_len - 3)
      && (subject[0] == '<')
      && (subject[subject_len - 1 - x509_domain_len - 1] == '@')
      && (! strncmp (subject + subject_len - x509_domain_len - 1, x509_domain, x509_domain_len))
      && (subject[subject_len - 1] == '>'))
    return 1;
  else
    return 0;
}

/* Extracts the mailbox name from the e-mail address ADDRESS and store
   it in *ACCOUNT.  ADDRESS must be a string of the form "<x@y>", in
   this case *ACCOUNT will be the newly allocated string "x".  Returns
   proper error code. */
static gpg_error_t
email_address_extract_account (const char *address, char **account)
{
  gpg_error_t err;
  char *name;
  size_t name_len;
  char *p;

  err = 0;
  name = NULL;

  p = strchr (address, '@');
  name_len = p - (address + 1);
  name = malloc (name_len + 1);
  if (!name)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  strncpy (name, address + 1, name_len);
  name[name_len] = 0;
  *account = name;

 out:

  return err;
}

/* This function takes the X509 certificate CERT, iterates through the
   e-mail addresses contained in CERT and returns the mailbox name of
   the first address with the domain part being X509_DOMAIN.  Returns
   proper error code.  */
static gpg_error_t
extract_username_from_cert (ksba_cert_t cert,
			    const char *x509_domain, char **username)
{
  gpg_error_t err;
  unsigned int idx;
  char *subject;
  int found;
  char *account;

  err = 0;
  found = 0;
  account = NULL;

  /* Iterate over subject items contained in certificate.  */
  for (idx = 0; (subject = ksba_cert_get_subject (cert, idx)); idx++)
    {
      if (!idx)
        {
	  /* Kludge for the DN (idx == 0).  */
          char *kludge_uid = email_kludge (subject);
          if (kludge_uid)
	    {
	      if (email_address_match (kludge_uid, x509_domain))
		{
		  found = 1;
		  err = email_address_extract_account (kludge_uid, &account);
		}
	      free (kludge_uid);
	    }
        }
      else
	{
	  if (email_address_match (subject, x509_domain))
	    {
	      found = 1;
	      err = email_address_extract_account (subject, &account);
	    }
	}

      ksba_free (subject);

      if (found)
	break;
    }

  if (found)
    {
      if (!err)
	*username = account;
    }
  else
    err = gpg_error (GPG_ERR_UNSUPPORTED_CERT); /* FIXME: wrong err
						   code?  */

  return err;
}

static gpg_error_t
lookup_cert (poldi_ctx_t ctx, dirmngr_ctx_t dirmngr, const char *url,
	     ksba_cert_t *certificate)
{
  ksba_cert_t cert;
  gpg_error_t err;

  cert = NULL;
  err = 0;

  if (!url)
    {
      //log_error ("[Poldi] ")
      err = GPG_ERR_INV_CARD;
      goto out;
    }

  if (strncmp (url, "ldap://", 7) == 0)
    err = dirmngr_lookup_url (dirmngr, url, &cert);
  else if (strncmp (ctx->cardinfo.pubkey_url, "file://", 7) == 0)
    err = lookup_cert_from_file (ctx->cardinfo.pubkey_url + 7, &cert);
  else
    {
      /* FIXME, log/conv? */
      err = GPG_ERR_INV_CARD;
    }
  if (err)
    goto out;

  *certificate = cert;

 out:

  if (err)
    ksba_cert_release (cert);

  return err;
}



/* Entry point for the x509 authentication method. Returns TRUE (1) if
   authentication succeeded and FALSE (0) otherwise. */
static int
auth_method_x509_auth_do (poldi_ctx_t ctx, x509_ctx_t cookie,
			  const char *username_desired,
			  char **username_authenticated)
{
  unsigned char *challenge;
  unsigned char *response;
  size_t challenge_n;
  size_t response_n;
  gpg_error_t err;
  char *card_username;
  ksba_cert_t cert;
  dirmngr_ctx_t dirmngr;
  struct getpin_cb_data cb_data;

  dirmngr = NULL;
  challenge = NULL;
  response = NULL;
  card_username = NULL;
  cert = NULL;
  err = 0;

  /*** Sanity checks. ***/

  if (! (cookie->x509_domain && cookie->dirmngr_socket))
    {
      err = gpg_error (GPG_ERR_CONFIGURATION);
      log_error ("x509 authentication method not properly configured\n");
      goto out;
    }

  /*** Connect to Dirmngr. ***/

  err = dirmngr_connect (&dirmngr, cookie->dirmngr_socket, 0);
  if (err)
    goto out;

  // /*** Receive card info. ***/

  if (ctx->debug)
    log_info ("Public key url is: '%s'\n", ctx->cardinfo.pubkey_url);

  /*** Fetch certificate. ***/

  err = lookup_cert (ctx, dirmngr, ctx->cardinfo.pubkey_url, &cert);
  if (err)
    {
      log_error ("failed to look up certificate `%s': %s",
		 ctx->cardinfo.pubkey_url, gpg_strerror (err));
      goto out;
    }

  /*** Valide cert. ***/

  /* FIXME: implement mechanism which allows for specifying the
     issuer? */

  err = dirmngr_validate (dirmngr, cert);
  if (err)
    goto out;

  /*** Check username. ***/

  err = extract_username_from_cert (cert, cookie->x509_domain, &card_username);
  if (err)
    goto out;

  //

  if (username_desired)
    {
      /* Application wants us to authenticate the user as
	 PAM_USERNAME.  */
      if (strcmp (username_desired, card_username) != 0)
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
      log_error ("failed to generate challenge: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /*** Let card sign the challenge. ***/

  cb_data.conv = ctx->conv;
  err = scd_pksign (ctx->scd, "OPENPGP.3",
		    getpin_cb, &cb_data,
		    challenge, challenge_n,
		    &response, &response_n);
  if (err)
    {
      log_error ("failed to retrieve challenge signature from card: %s\n",
		 gpg_strerror (err));
      goto out;
    }

  /*** Verify challenge signature against certificate. ***/

  err = verify_challenge_sig (ctx, cert,
			      challenge, challenge_n,
			      response, response_n);
  if (err)
    {
      log_error ("failed to verify challenge\n");
      goto out;
    }

  /* Auth succeeded.  */

  if (!username_desired)
    *username_authenticated = card_username;

 out:

  /* Release resources.  */
  dirmngr_disconnect (dirmngr);
  ksba_cert_release (cert);

  if (err)
    free (card_username);

  /* Log result.  */
  if (err)
    log_error ("Failure: %s\n", gpg_strerror (err));
  else
    log_info ("Success\n");

  return !err;
}

static int
auth_method_x509_auth (poldi_ctx_t ctx, void *cookie, char **username)
{
  return auth_method_x509_auth_do (ctx, cookie, NULL, username);
}

static int
auth_method_x509_auth_as (poldi_ctx_t ctx, void *cookie, const char *username)
{
  return auth_method_x509_auth_do (ctx, cookie, username, NULL);
}



struct auth_method_s auth_method_x509 =
  {
    auth_method_x509_init,
    auth_method_x509_deinit,
    auth_method_x509_parsecb,
    auth_method_x509_auth,
    auth_method_x509_auth_as,
    x509_arg_opts,
    POLDI_CONF_DIRECTORY "/" "poldi-x509.conf" /* FIXME? */
  };
