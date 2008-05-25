/* dirmngr.c - Poldi dirmngr access layer
 *	Copyright (C) 2002, 2003, 2005, 2007, 2008 Free Software Foundation, Inc.
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
#include <ksba.h>

#include "assuan.h"
#include "util/util.h"
#include "util/membuf.h"
#include "dirmngr.h"

/* FIXME: compare with original file, figure out why these are not
   needed. */
//#include "i18n.h"
//#include "keydb.h"
//#include "fingerprint.h"



/* FIXME!!! */
#define PATHSEP_C ':'
#define _(s) s

struct dirmngr_ctx_s
{
  assuan_context_t assuan;
};

#if 0
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
#endif

struct lookup_parm_s {
  /* FIXME? */
  //assuan_context_t ctx;
  void (*cb)(void *, ksba_cert_t);
  void *cb_value;
  membuf_t data;
  gpg_error_t err;
};



gpg_error_t
dirmngr_connect (dirmngr_ctx_t *ctx,
		 const char *sock,
		 unsigned int flags)
{
  dirmngr_ctx_t context;
  gpg_error_t err;

  context = NULL;

  context = malloc (sizeof (*context));
  if (!context)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  context->assuan = NULL;
  err = assuan_socket_connect (&context->assuan, sock, -1);
  if (err)
    goto out;

  *ctx = context;

 out:

  if (err)
    free (context);

  return err;
}

void
dirmngr_disconnect (dirmngr_ctx_t ctx)
{
  if (ctx)
    {
      if (ctx->assuan)
	assuan_disconnect (ctx->assuan);
      free (ctx);
    }
}




/* Communication structure for the certificate inquire callback. */
struct inq_cert_parm_s
{
  assuan_context_t ctx;
  const unsigned char *cert;
  size_t certlen;
};

/* Callback for the inquire fiunction to send back the certificate.  */
static int
inq_cert (void *opaque, const char *line)
{
  struct inq_cert_parm_s *parm = opaque;
  gpg_error_t err;

  if (!strncmp (line, "TARGETCERT", 10) && (line[10] == ' ' || !line[10]))
    {
      err = assuan_send_data (parm->ctx, parm->cert, parm->certlen);
    }
  else if ((!strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8]))
	   || (!strncmp (line, "SENDCERT_SKI", 12) && (line[12]==' ' || !line[12]))
	   || (!strncmp (line, "SENDISSUERCERT", 14) && (line[14] == ' ' || !line[14])))
    
    {
      /* We don't support this but dirmngr might ask for it.  So
         simply ignore it by sending back and empty value. */
      err = assuan_send_data (parm->ctx, NULL, 0);
    }
  else
    {
      log_info (_("unsupported inquiry `%s'\n"), line);
      err = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
      /* Note that this error will let assuan_transact terminate
         immediately instead of return the error to the caller.  It is
         not clear whether this is the desired behaviour - it may
         change in future. */
    }

  return err;
}

gpg_error_t
dirmngr_validate (dirmngr_ctx_t ctx, ksba_cert_t cert)
{
  struct inq_cert_parm_s parm;
  const unsigned char *image;
  size_t imagelen;
  gpg_error_t err;

  err = 0;

  image = ksba_cert_get_image (cert, &imagelen);
  if (!image)
    {
      err = GPG_ERR_INTERNAL;	/* FIXME: what error code? */
      goto out;
    }

  /* Setup PARM structure.  */
  parm.ctx = ctx->assuan;
  parm.cert = image;
  parm.certlen = imagelen;

  err = assuan_transact (ctx->assuan, "VALIDATE", NULL, NULL,
			 inq_cert, &parm,
			 NULL, NULL);
  /* FIXME: logging? */

 out:

  return err;

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
