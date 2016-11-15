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

/* See dirmngr.h for a description of the dirmngr access API
   implemented by this file. */

#include <poldi.h>

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

#include <util/simplelog.h>



/* This is the a "dirmngr context". */
struct dirmngr_ctx_s
{
  assuan_context_t assuan;	/* Assuan context for accessing
				   dirmngr. */
  log_handle_t log_handle;	/* Handle for logging messages. */
};

/* This structure is used for passing data to the "data callback"
   during assuan transactions. */
struct lookup_parm_s {
  void (*cb) (void *, ksba_cert_t);
  void *cb_value;
  membuf_t data;
  gpg_error_t err;
  dirmngr_ctx_t ctx;
};



static struct dirmngr_ctx_s dirmngr_ctx_init; /* For initialization
						 purpose. */

/* Connect to a running dirmngr through the local socket named by
   SOCK, using LOG_HANDLE as logging handle and flags FLAGS. The new
   context is stored in *CTX.  Returns proper error code. */
gpg_error_t
dirmngr_connect (dirmngr_ctx_t *ctx,
		 const char *sock,
		 unsigned int flags,
		 log_handle_t log_handle)
{
  dirmngr_ctx_t context;
  gpg_error_t err;

  /* Allocate.  */
  context = xtrymalloc (sizeof (*context));
  if (!context)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  /* Initialize with zeroes. */
  *context = dirmngr_ctx_init;

  /* Connect to assuan server. */
  err = assuan_socket_connect (&context->assuan, sock, -1);
  if (err)
    goto out;

  /* Install logging handle in new context. */
  context->log_handle = log_handle;

  *ctx = context;

 out:

  if (err)
    xfree (context);
  
  return err;
}

/* Close the dirmngr connection associated with CTX and release all
   related resources. */
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




/* Communication structure for the certificate inquire callback. For
   the assuan VALIDATE command. */
struct inq_cert_parm_s
{
  dirmngr_ctx_t ctx;		/* Dirmngr context of the caller. */
  const unsigned char *cert;	/* Raw certificate in question. */
  size_t certlen;		/* Length of certificate in bytes. */
};

/* Callback for the inquire function to send back the
   certificate. Sending of a certificate to Dirmngr is used for
   validation purpose. */
static int
inq_cert (void *opaque, const char *line)
{
  struct inq_cert_parm_s *parm = opaque;
  gpg_error_t err;

  if (!strncmp (line, "TARGETCERT", 10) && (line[10] == ' ' || !line[10]))
    /* Send back the certificate we want to validate. */
    err = assuan_send_data (parm->ctx->assuan, parm->cert, parm->certlen);
  else if ((!strncmp (line, "SENDCERT", 8) && (line[8] == ' ' || !line[8]))
	   || (!strncmp (line, "SENDCERT_SKI", 12) && (line[12]==' ' || !line[12]))
	   || (!strncmp (line, "SENDISSUERCERT", 14) && (line[14] == ' ' || !line[14])))
    {
      /* We don't support this but dirmngr might ask for it.  So
	 simply ignore it by sending back an empty value. */
      log_msg_debug (parm->ctx->log_handle, "ignored inquiry from dirmngr: `%s'", line);
      err = assuan_send_data (parm->ctx->assuan, NULL, 0);
      if (err)
	log_msg_error (parm->ctx->log_handle,
		       _("failed to send back empty value to dirmngr: %s"),
		       gpg_strerror (err));
    }
  else
    {
      log_msg_error (parm->ctx->log_handle, _("unsupported assuan inquiry `%s'"), line);
      err = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
      /* Note that this error will let assuan_transact terminate
         immediately instead of return the error to the caller.  It is
         not clear whether this is the desired behaviour - it may
         change in future. */
    }

  return err;
}

/* Validate the certificate CERT through the dirmngr context
   CTX. Returns zero in case the certificate is considered valid, an
   appropriate error code otherwise. */
gpg_error_t
dirmngr_validate (dirmngr_ctx_t ctx, ksba_cert_t cert)
{
  struct inq_cert_parm_s parm;
  const unsigned char *image;
  size_t imagelen;
  gpg_error_t err;

  assert (ctx);
  assert (cert);

  err = 0;

  /* Retrieve pointer to the raw certificate data. */
  image = ksba_cert_get_image (cert, &imagelen);
  if (!image)
    {
      err = gpg_error (GPG_ERR_INTERNAL);	/* FIXME: what error code? */
      goto out;
    }

  /* Setup PARM structure.  */
  parm.ctx = ctx;
  parm.cert = image;
  parm.certlen = imagelen;

  /* Validate certificate. INQ_CERT is the callback that will send the
     certificate in question to dirmngr. */
  err = assuan_transact (ctx->assuan, "VALIDATE", NULL, NULL,
			 inq_cert, &parm,
			 NULL, NULL);
 out:

  return err;
}



/* Lookup helpers*/
static int
lookup_cb (void *opaque, const void *buffer, size_t length)
{
  struct lookup_parm_s *parm = opaque;

  if (parm->err)
    /* Already triggered an error => do nothing.  */
    return 0;

  if (buffer)
    {
      /* Add more data into the buffer and return. */
      put_membuf (&parm->data, buffer, length);
      return 0;
    }
  else
    {
      /* END encountered - process what we have. */

      size_t len;
      char *buf;
      ksba_cert_t cert;
      gpg_error_t rc;

      /* Retrieve pointer to accumulated data. */
      buf = get_membuf (&parm->data, &len);
      if (!buf)
	{
	  parm->err = gpg_error (GPG_ERR_ENOMEM);
	  return 0;
	}

      /* Create new certificate object from raw data. */
      rc = ksba_cert_new (&cert);
      if (rc)
	{
	  parm->err = rc;
	  return 0;
	}
      rc = ksba_cert_init_from_mem (cert, buf, len);
      if (rc)
	{
	  log_msg_error (parm->ctx->log_handle,
			 _("failed to create new ksba certificate object: %s"),
			 gpg_strerror (rc));
	  /* FIXME: better error handling?  -mo */
	}
      else
	{
	  parm->cb (parm->cb_value, cert);
	}

      ksba_cert_release (cert);
      init_membuf (&parm->data, 4096); /* FIXME: what is this for?? -mo */
    }

  return 0;
}

/* FIXME: simplify -mo */
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

/* Retrieve the certificate stored under the url URL through the
   dirmngr context CTX and store it in *CERTIFICATE.  Returns proper
   error code. */
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

  parm.cb = lookup_url_cb;
  parm.cb_value = &cert;
  parm.err = 0;
  init_membuf (&parm.data, 4096);
  parm.ctx = ctx;

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
      err = GPG_ERR_GENERAL;	/* FIXME: better error code? -mo */
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

/* END */
