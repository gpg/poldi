/* dirmngr.c - communication with dirmngr 
 *	Copyright (C) 2002, 2003, 2005, 2007 Free Software Foundation, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h> 
#include <time.h>
#include <assert.h>
#include <ctype.h>

#include <gcrypt.h>
#include <assuan.h>
#include <ksba.h>

#include "common/util.h"
#include "common/membuf.h"
#include "dirmngr.h"

//#include "i18n.h"
//#include "keydb.h"

#include "fingerprint.h"



/* FIXME!!! */
#define PATHSEP_C ':'
#define _(s) s

struct dirmngr_ctx_s
{
  assuan_context_t assuan;
};

struct inq_certificate_parm_s {
  assuan_context_t ctx;
  ksba_cert_t cert;
  ksba_cert_t issuer_cert;
};

struct isvalid_status_parm_s {
  //ctrl_t ctrl;
  int seen;
  unsigned char fpr[20];
};

struct lookup_parm_s {
  /* FIXME? */
  //assuan_context_t ctx;
  void (*cb)(void *, ksba_cert_t);
  void *cb_value;
  membuf_t data;
  gpg_error_t err;
};

#if 0

struct run_command_parm_s {
  assuan_context_t ctx;
};
#endif



static gpg_error_t
extract_socket_from_infostr (const char *infostr, char **socketname)
{
  gpg_error_t err;
  char *infostr_cp;
  char *p;
  int prot;
  int pid;

  err = 0;

  infostr_cp = strdup (infostr);
  if (!infostr_cp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  p = strchr (infostr_cp, PATHSEP_C);
  if (!p || (p == infostr_cp))
    {
      log_error (_("malformed DIRMNGR_INFO environment variable\n"));
      err = GPG_ERR_NO_DIRMNGR;
      goto out;
    }

  *p++ = 0;
  pid = atoi (p);
  /* Skip PID.  */
  while (*p && *p != PATHSEP_C)
    p++;

  prot = *p ? atoi (p+1) : 0;
  if (prot != 1)
    {
      log_error (_("dirmngr protocol version %d is not supported\n"),
		 prot);
      err = GPG_ERR_NO_DIRMNGR;
      goto out;
    }

  *socketname = infostr_cp;

 out:

  if (err)
    xfree (infostr_cp);

  return err;
}

static gpg_error_t
connect_socket (dirmngr_ctx_t ctx, const char *infostr)
{
  assuan_context_t assuan_ctx;
  char *socketname;
  gpg_error_t err;

  assuan_ctx = NULL;
  socketname = NULL;

  err = extract_socket_from_infostr (infostr, &socketname);
  if (err)
    goto out;

  err = assuan_socket_connect (&assuan_ctx, socketname, -1);
  if (err)
    goto out;

  ctx->assuan = assuan_ctx;

 out:

  xfree (socketname);

  return err;
}

static gpg_error_t
connect_pipe (dirmngr_ctx_t ctx, const char *path)
{
  assuan_context_t assuan_ctx;
  gpg_error_t err;
  const char *argv[3];
  const char *pgmname;
  int no_close_list[3];
  int i;

  assuan_ctx = NULL;
  err = 0;

  if ((!path) || (!*path))
    path = GNUPG_DEFAULT_DIRMNGR;
  pgmname = strrchr (path, '/');
  if (!pgmname)
    pgmname = path;
  else
    pgmname++;

  argv[0] = pgmname;
  argv[1] = "--server";
  argv[2] = NULL;

  i=0;
  if (log_get_fd () != -1)
    no_close_list[i++] = log_get_fd ();
  no_close_list[i++] = fileno (stderr);
  no_close_list[i] = -1;

  err = assuan_pipe_connect (&assuan_ctx, path, argv, no_close_list);
  if (err)
    goto out;

  ctx->assuan = assuan_ctx;

 out:

  return err;
}

gpg_error_t
dirmngr_connect (dirmngr_ctx_t *ctx,
		 const char *infostr,
		 const char *path,
		 unsigned int flags)
{
  dirmngr_ctx_t context;
  gpg_error_t err;

  context = NULL;

  context = xtrymalloc (sizeof (*context));
  if (!context)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  context->assuan = NULL;

  if (infostr)
    err = connect_socket (context, infostr);
  else
    err = connect_pipe (context, path);

  if (err)
    goto out;

  *ctx = context;

 out:

  if (err)
    xfree (context);

  return err;
}

void
dirmngr_disconnect (dirmngr_ctx_t ctx)
{
  if (ctx)
    {
      if (ctx->assuan)
	assuan_disconnect (ctx->assuan);
      xfree (ctx);
    }
}




/* Handle a SENDCERT inquiry. */
static int
inq_certificate (void *opaque, const char *line)
{
  struct inq_certificate_parm_s *parm = opaque;
  int rc;
  const unsigned char *der;
  size_t derlen;
  ksba_sexp_t ski = NULL;

  if (!strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8]))
    {
      line += 8;
    }
  else if (!strncmp (line, "SENDCERT_SKI", 12) && (line[12]==' ' || !line[12]))
    {
      size_t n;

      /* Send a certificate where a sourceKeyIdentifier is included. */
      line += 12;
      while (*line == ' ')
        line++;
      ski = make_simple_sexp_from_hexstr (line, &n);
      line += n;
      while (*line == ' ')
        line++;
    }
  else
    {
      /* Note: we do not support SENDISSUERCERT.  */
      log_error ("unsupported inquiry `%s'\n", line);
      return gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  if (!*line)
    { /* Send the current certificate. */
#if 0
      der = ksba_cert_get_image (issuer_mode? parm->issuer_cert : parm->cert,
                                 &derlen);
#else
      der = ksba_cert_get_image (parm->cert, &derlen);
#endif
      if (!der)
        rc = gpg_error (GPG_ERR_INV_CERT_OBJ);
      else
        rc = assuan_send_data (parm->ctx, der, derlen);
    }
  else 
    {
      /* Send the given certificate. */
#if 0
      int err;
      ksba_cert_t cert;
      err = gpgsm_find_cert (line, ski, &cert);
      if (err)
        {
          log_error ("certificate not found: %s\n", gpg_strerror (err));
          rc = gpg_error (GPG_ERR_NOT_FOUND);
        }
      else
        {
          der = ksba_cert_get_image (cert, &derlen);
          if (!der)
            rc = gpg_error (GPG_ERR_INV_CERT_OBJ);
          else
            rc = assuan_send_data (parm->ctx, der, derlen);
          ksba_cert_release (cert);
        }
#else
      rc = gpg_error (GPG_ERR_NOT_FOUND);
#endif
    }

  xfree (ski);
  return rc; 
}

/* Take a 20 byte hexencoded string and put it into the the provided
   20 byte buffer FPR in binary format. */
static int
unhexify_fpr (const char *hexstr, unsigned char *fpr)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n != 40))
    return 0; /* no fingerprint (invalid or wrong length). */
  n /= 2;
  for (s=hexstr, n=0; *s; s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* okay */
}

static assuan_error_t
isvalid_status_cb (void *opaque, const char *line)
{
  struct isvalid_status_parm_s *parm = opaque;

  if (!strncmp (line, "ONLY_VALID_IF_CERT_VALID", 24)
      && (line[24]==' ' || !line[24]))
    {
      parm->seen++;
      if (!line[24] || !unhexify_fpr (line+25, parm->fpr))
        parm->seen++; /* Bumb it to indicate an error. */
    }
  return 0;
}



/* Call the directory manager to check whether the certificate is valid
   Returns 0 for valid or usually one of the errors:

  GPG_ERR_CERTIFICATE_REVOKED
  GPG_ERR_NO_CRL_KNOWN
  GPG_ERR_CRL_TOO_OLD

  Values for USE_OCSP:
     0 = Do CRL check.
     1 = Do an OCSP check.
     2 = Do an OCSP check using only the default responder.
 */
gpg_error_t
dirmngr_isvalid (dirmngr_ctx_t ctx, ksba_cert_t cert)
{
  /* FIXME: use_ocsp flag - integrate in CTX? */
  int use_ocsp = 1;
  gpg_error_t rc;
  char *certid;
  char line[ASSUAN_LINELENGTH];
  struct inq_certificate_parm_s parm;
  struct isvalid_status_parm_s stparm;

  if (use_ocsp)
    {
      certid = gpgsm_get_fingerprint_hexstring (cert, GCRY_MD_SHA1);
    }
  else
    {
      certid = gpgsm_get_certid (cert);
      if (!certid)
        {
          log_error ("error getting the certificate ID\n");
          return gpg_error (GPG_ERR_GENERAL);
        }
    }

  /* FIXME: integrate verbose opt in CTX.  */
  //if (opt.verbose > 1)
  if (1)
    {
      char *fpr = gpgsm_get_fingerprint_string (cert, GCRY_MD_SHA1);
      log_info ("asking dirmngr about %s%s\n", fpr,
                use_ocsp? " (using OCSP)":"");
      xfree (fpr);
    }

  parm.ctx = ctx->assuan;
  parm.cert = cert;
  //FIXME?
  //parm.issuer_cert = issuer_cert;

  //stparm.ctrl = ctrl;
  stparm.seen = 0;
  memset (stparm.fpr, 0, 20);

  /* FIXME: If --disable-crl-checks has been set, we should pass an
     option to dirmngr, so that no fallback CRL check is done after an
     ocsp check.  It is not a problem right now as dirmngr does not
     fallback to CRL checking.  */

  /* It is sufficient to send the options only once because we have
     one connection per process only. */
  /* FIXME: integrate DID_OPTIONS flag in CTX?  */
#if 0
  if (!did_options)
    {
      if (opt.force_crl_refresh)
        assuan_transact (dirmngr_ctx, "OPTION force-crl-refresh=1",
                         NULL, NULL, NULL, NULL, NULL, NULL);
      did_options = 1;
    }
#endif

  snprintf (line, DIM(line)-1, "ISVALID%s %s", 
            use_ocsp == 2? " --only-ocsp --force-default-responder":"",
            certid);
  line[DIM(line)-1] = 0;
  xfree (certid);

  rc = assuan_transact (ctx->assuan, line, NULL, NULL,
                        inq_certificate, &parm,
                        isvalid_status_cb, &stparm);
  /* FIXME: integrate verbose otp in CTX.  */
  //if (opt.verbose > 1)
  if (1)
    log_info ("response of dirmngr: %s\n", rc? gpg_strerror (rc): "okay");
  rc = rc;

  if (!rc && stparm.seen)
    {
      /* Need to also check the certificate validity. */
      if (stparm.seen != 1)
        {
          log_error ("communication problem with dirmngr detected\n");
          rc = gpg_error (GPG_ERR_INV_CRL);
        }
      else
        {
#if 0
          KEYDB_HANDLE kh;
          ksba_cert_t rspcert = NULL;

          /* Fixme: First try to get the certificate from the
             dirmngr's cache - it should be there. */
          kh = keydb_new (0);
          if (!kh)
            rc = gpg_error (GPG_ERR_ENOMEM);
          if (!rc)
            rc = keydb_search_fpr (kh, stparm.fpr);
          if (!rc)
            rc = keydb_get_cert (kh, &rspcert);
          if (rc)
            {
              log_error ("unable to find the certificate used "
                         "by the dirmngr: %s\n", gpg_strerror (rc));
              rc = gpg_error (GPG_ERR_INV_CRL);
            }
          keydb_release (kh);

          if (!rc)
            {
              rc = gpgsm_cert_use_ocsp_p (rspcert);
              if (rc)
                rc = gpg_error (GPG_ERR_INV_CRL);
              else
                {
                  /* Note the no_dirmngr flag: This avoids checking
                     this certificate over and over again. */
                  rc = gpgsm_validate_chain (ctrl, rspcert, "", NULL, 0, NULL, 
                                             VALIDATE_FLAG_NO_DIRMNGR, NULL);
                  if (rc)
                    {
                      log_error ("invalid certificate used for CRL/OCSP: %s\n",
                                 gpg_strerror (rc));
                      rc = gpg_error (GPG_ERR_INV_CRL);
                    }
                }
            }
          ksba_cert_release (rspcert);
#else
	  rc = gpg_error (GPG_ERR_GENERAL);
#endif
        }
    }
  return rc;
}



/* Lookup helpers*/
static int
lookup_cb (void *opaque, const void *buffer, size_t length)
{
  
  struct lookup_parm_s *parm = opaque;
  size_t len;
  char *buf;
  ksba_cert_t cert;
  gpg_error_t rc;

  if (parm->err)
    /* Already triggered an error => do nothing.  */
    return 0;

  if (buffer)
    {
      put_membuf (&parm->data, buffer, length);
      return 0;
    }
  /* END encountered - process what we have */
  buf = get_membuf (&parm->data, &len);
  if (!buf)
    {
      parm->err = gpg_error (GPG_ERR_ENOMEM);
      return 0;
    }

  rc = ksba_cert_new (&cert);
  if (rc)
    {
      parm->err = rc;
      return 0;
    }
  rc = ksba_cert_init_from_mem (cert, buf, len);
  if (rc)
    {
      log_error ("failed to parse a certificate: %s\n", gpg_strerror (rc));
    }
  else
    {
      parm->cb (parm->cb_value, cert);
    }

  ksba_cert_release (cert);
  init_membuf (&parm->data, 4096);

  return 0;
}

static void
lookup_url_cb (void *opaque, ksba_cert_t cert)
{
  ksba_cert_t *cert_cp = opaque;

  if (*cert_cp)
    /* Does already contain a cert.  */
    return;

  ksba_cert_ref (cert);
  *cert_cp = cert;
}

/* Run the Directroy Managers lookup command using the pattern
   compiled from the strings given in NAMES.  The caller must provide
   the callback CB which will be passed cert by cert.  Note that CTRL
   is optional. */
gpg_error_t 
dirmngr_lookup_url (dirmngr_ctx_t ctx,
		    const char *url, ksba_cert_t *certificate)
{ 
  gpg_error_t err;
  char line[ASSUAN_LINELENGTH];
  struct lookup_parm_s parm;
  ksba_cert_t cert;

  cert = NULL;
  err = 0;

  /* Prepare command.  */

  snprintf (line, DIM(line)-1, "LOOKUP --url %s", url);
  line[DIM(line)-1] = 0;

  //parm.ctx = dirmngr_ctx->assuan;
  parm.cb = lookup_url_cb;
  parm.cb_value = &cert;
  parm.err = 0;
  init_membuf (&parm.data, 4096);

  /* Execute command.  */

  err = assuan_transact (ctx->assuan, line, lookup_cb, &parm,
			 NULL, NULL, NULL, NULL);
  if (err)
    goto out;
  if (parm.err)
    {
      err = parm.err;
      goto out;
    }
  if (!cert)
    {
      err = GPG_ERR_GENERAL;	/* FIXME? */
      goto out;
    }

 out:

  xfree (get_membuf (&parm.data, NULL));

  if (err)
    {
      if (cert)
	{
	  ksba_cert_release (cert);
	  cert = NULL;
	}
    }
  else
    *certificate = cert;

  return err;
}
