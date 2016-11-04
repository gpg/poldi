/* scd.c - Interface to Scdaemon
   Copyright (C) 2001, 2002, 2005 Free Software Foundation, Inc.
   Copyright (C) 2007, 2008, 2009 g10code GmbH. 

   This file is part of Poldi.
 
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
 
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
 
   You should have received a copy of the GNU General Public License
   along with this program; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <poldi.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <gpg-error.h>
#include <gcrypt.h>

#include "scd.h"
#include "assuan.h"
#include "util/util.h"
#include "util/membuf.h"
#include "util/support.h"
#include "util/simplelog.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif



/* Initializer objet for struct scd_cardinfo instances.  */
struct scd_cardinfo scd_cardinfo_null;



struct scd_context
{
  assuan_context_t assuan_ctx;
  unsigned int flags;
  log_handle_t loghandle;
  scd_pincb_t pincb;
  void *pincb_cookie;
};

/* Callback parameter for learn card */
struct learn_parm_s
{
  void (*kpinfo_cb)(void*, const char *);
  void *kpinfo_cb_arg;
  void (*certinfo_cb)(void*, const char *);
  void *certinfo_cb_arg;
  void (*sinfo_cb)(void*, const char *, size_t, const char *);
  void *sinfo_cb_arg;
};

struct inq_needpin_s 
{
  scd_context_t ctx;
  int (*getpin_cb)(void *, const char *, char*, size_t);
  void *getpin_cb_arg;
};


/* Local prototypes.  */
static assuan_error_t membuf_data_cb (void *opaque,
                                      const void *buffer, size_t length);




static gpg_error_t scd_serialno_internal (assuan_context_t ctx,
					  char **r_serialno);


/* Send a RESTART to SCDaemon.  */
static void
restart_scd (scd_context_t ctx)
{
  assuan_transact (ctx->assuan_ctx, "RESTART",
		   NULL, NULL, NULL, NULL, NULL, NULL);
}



/* Fork off scdaemon and work by pipes.  Returns proper error code or
   zero on success.  */
gpg_error_t
scd_connect (scd_context_t *scd_ctx, const char *scd_path,
	     const char *scd_options, log_handle_t loghandle)
{
  assuan_context_t assuan_ctx;
  scd_context_t ctx;
  int rc = 0;

  assuan_ctx = NULL;

  ctx = xtrymalloc (sizeof (*ctx));
  if (! ctx)
    {
      rc = gpg_error_from_syserror ();
      goto out;
    }

  ctx->assuan_ctx = NULL;
  ctx->flags = 0;

  if (1)
    {
      const char *pgmname;
      const char *argv[5];
      int no_close_list[3];
      int i;

#if 0
	log_msg_debug (loghandle,
		       _("no running scdaemon - starting one"));
#endif

      if (fflush (NULL))
        {
          rc = gpg_error_from_syserror ();
	  log_msg_error (loghandle,
			 _("error flushing pending output: %s"),
			 strerror (errno));
	  goto out;
        }

      if (!scd_path || !*scd_path)
        scd_path = GNUPG_DEFAULT_SCD;
      if ( !(pgmname = strrchr (scd_path, '/')))
        pgmname = scd_path;
      else
        pgmname++;

      /* Fill argument vector for scdaemon.  */

      i = 0;
      argv[i++] = pgmname;
      argv[i++] = "--server";
      if (scd_options)
	{
	  argv[i++] = "--options";
	  argv[i++] = scd_options;
	}
      argv[i++] = NULL;

      i=0;

      /* FIXME! Am I right in assumung that we do not need this?
	 -mo */
#if 0
      if (log_get_fd () != -1)
        no_close_list[i++] = log_get_fd ();
#endif

      /* FIXME: What about stderr? */
      no_close_list[i++] = fileno (stderr);
      no_close_list[i] = -1;

      /* connect to the scdaemon and perform initial handshaking */
      rc = assuan_pipe_connect (&assuan_ctx, scd_path, argv,
                                no_close_list);
      if (!rc)
	{
	  log_msg_debug (loghandle,
			 _("spawned a new scdaemon (path: '%s')"),
			 scd_path);
	  goto out;
	}
    }

  log_msg_error (loghandle,
		 _("could not connect to any scdaemon: %s"),
		 gpg_strerror (rc));

 out:

  if (rc)
    {
      assuan_disconnect (assuan_ctx);
      xfree (ctx);

    }
  else
    {
      /* FIXME: is this the best way?  -mo */
      //reset_scd (assuan_ctx);
      scd_serialno_internal (assuan_ctx, NULL);

      ctx->assuan_ctx = assuan_ctx;
      ctx->flags = 0;
      ctx->loghandle = loghandle;
      *scd_ctx = ctx;
#if 0
	log_msg_debug (loghandle,
		       _("connection to scdaemon established"));
#endif
    }

  return rc;
}

/* Disconnect from SCDaemon; destroy the context SCD_CTX.  */
void
scd_disconnect (scd_context_t scd_ctx)
{
  if (scd_ctx)
    {
      restart_scd (scd_ctx);
      assuan_disconnect (scd_ctx->assuan_ctx);
      xfree (scd_ctx);
    }
}


void
scd_set_pincb (scd_context_t scd_ctx,
	       scd_pincb_t pincb, void *cookie)
{
  assert (scd_ctx);

  scd_ctx->pincb = pincb;
  scd_ctx->pincb_cookie = cookie;
}




/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary Nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *
unescape_status_string (const char *s)
{
  char *buffer, *d;

  buffer = d = xtrymalloc (strlen ((const char*)s)+1);
  if (!buffer)
    return NULL;
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
  return buffer;
}




/* CARD LEARNING.  */

/* Take a 20 byte hexencoded string and put it into the the provided
   20 byte buffer FPR in binary format. */
static int
unhexify_fpr (const char *hexstr, char *fpr)
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

/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned. */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s=line; hexdigitp (s); s++)
    ;
  p = xtrymalloc (s + 1 - line);
  if (p)
    {
      memcpy (p, line, s-line);
      p[s-line] = 0;
    }
  return p;
}

static int
learn_status_cb (void *opaque, const char *line)
{
  struct scd_cardinfo *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  //int i;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      xfree (parm->serialno);
      parm->serialno = store_serialno (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      xfree (parm->disp_name);
      parm->disp_name = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      xfree (parm->disp_lang);
      parm->disp_lang = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      xfree (parm->pubkey_url);
      parm->pubkey_url = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      xfree (parm->login_data);
      parm->login_data = unescape_status_string (line);
    }
  else if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1valid = unhexify_fpr (line, parm->fpr1);
      else if (no == 2)
        parm->fpr2valid = unhexify_fpr (line, parm->fpr2);
      else if (no == 3)
        parm->fpr3valid = unhexify_fpr (line, parm->fpr3);
    }
  
  return 0;
}

/* Read information from card and fill the cardinfo structure
   CARDINFO.  Returns proper error code, zero on success.  */
int
scd_learn (scd_context_t ctx,
	   struct scd_cardinfo *cardinfo)
{
  int rc;

  *cardinfo = scd_cardinfo_null;
  rc = assuan_transact (ctx->assuan_ctx, "LEARN --force",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, cardinfo);

  return rc;
}

/* Simply release the cardinfo structure INFO.  INFO being NULL is
   okay.  */
void
scd_release_cardinfo (struct scd_cardinfo info)
{
  xfree (info.serialno);
  xfree (info.disp_name);
  xfree (info.login_data);
  xfree (info.pubkey_url);
}




/* CMD: SERIALNO.  */

static int
get_serialno_cb (void *opaque, const char *line)
{
  char **serialno = opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (*serialno)
        return gpg_error (GPG_ERR_CONFLICT); /* Unexpected status line. */
      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;
      if (!n || (n&1)|| !(spacep (s) || !*s) )
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      *serialno = xtrymalloc (n+1);
      if (!*serialno)
	return gpg_error_from_errno (errno);
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }

  return 0;
}

static gpg_error_t
scd_serialno_internal (assuan_context_t ctx, char **r_serialno)
{
  char *serialno;
  int rc;

  serialno = NULL;

  rc = assuan_transact (ctx, agent ? "SCD SERIALNO" : "SERIALNO",
                        NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  if (rc)
    goto out;

  if (r_serialno)
    *r_serialno = serialno;
  else
    xfree (serialno);

 out:

  return rc;
}

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
gpg_error_t
scd_serialno (scd_context_t ctx, char **r_serialno)
{
  gpg_error_t err;

  err = scd_serialno_internal (ctx->assuan_ctx, r_serialno);

  return err;
}

/* CMD: PKSIGN.  */



static int
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}
  
/* Handle the NEEDPIN inquiry. */
static int
inq_needpin (void *opaque, const char *line)
{
  struct inq_needpin_s *parm = opaque;
  char *pin;
  size_t pinlen;
  int rc;

  rc = 0;

  if (!strncmp (line, "NEEDPIN", 7) && (line[7] == ' ' || !line[7]))
    {
      if (!parm->getpin_cb)
	{
	  rc = GPG_ERR_BAD_PIN;
	  goto out;
	}

      line += 7;
      while (*line == ' ')
        line++;
      
      pinlen = 90;
      pin = xtrymalloc_secure (pinlen);
      if (!pin)
	{
	  rc = gpg_error_from_errno (errno);
	  goto out;
	}

      rc = parm->getpin_cb (parm->getpin_cb_arg, line, pin, pinlen);
      if (!rc)
        rc = assuan_send_data (parm->ctx->assuan_ctx, pin, pinlen);
      xfree (pin);
    }
  else if (!strncmp (line, "POPUPPINPADPROMPT", 17)
           && (line[17] == ' ' || !line[17]))
    {
      if (!parm->getpin_cb)
	{
	  rc = GPG_ERR_BAD_PIN;
	  goto out;
	}

      line += 17;
      while (*line == ' ')
        line++;
      
      rc = parm->getpin_cb (parm->getpin_cb_arg, line, NULL, 1);
    }
  else if (!strncmp (line, "DISMISSPINPADPROMPT", 19)
           && (line[19] == ' ' || !line[19]))
    {
      if (!parm->getpin_cb)
	{
	  rc = GPG_ERR_BAD_PIN;
	  goto out;
	}

      rc = parm->getpin_cb (parm->getpin_cb_arg, "", NULL, 0);
    }
  else
    {
      log_msg_error (parm->ctx->loghandle,
		     "received unsupported inquiry from scdaemon `%s'",
		     line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

 out:

  return gpg_error (rc);
}


/* Create a signature using the current card. CTX is the handle for
   the scd subsystem.  KEYID identifies the key on the card to use for
   signing. GETPIN_CB is the callback, which is called for querying of
   the PIN, GETPIN_CB_ARG is passed as opaque argument to
   GETPIN_CB. INDATA/INDATALEN is the input for the signature
   function.  The signature created is written into newly allocated
   memory in *R_BUF, *R_BUFLEN will hold the length of the
   signature. */
gpg_error_t
scd_pksign (scd_context_t ctx,
	    const char *keyid,
	    const unsigned char *indata, size_t indatalen,
	    unsigned char **r_buf, size_t *r_buflen)
{
  int rc;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_s inqparm;
  size_t len;
  unsigned char *sigbuf;
  size_t sigbuflen;

  *r_buf = NULL;
  *r_buflen = 0;
  rc = 0;

  init_membuf (&data, 1024);

  if (indatalen*2 + 50 > DIM(line)) /* FIXME: Are such long inputs
				       allowed? Should we handle them
				       differently?  */
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      goto out;
    }

  /* Inform scdaemon about the data to be signed. */

  sprintf (line, "SETDATA ");
  p = line + strlen (line);
  bin2hex (indata, indatalen, p);

  rc = assuan_transact (ctx->assuan_ctx, line,
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    goto out;

  /* Setup NEEDPIN inquiry handler.  */

  inqparm.ctx = ctx;
  inqparm.getpin_cb = ctx->pincb;
  inqparm.getpin_cb_arg = ctx->pincb_cookie;

  /* Go, sign it. */

  snprintf (line, DIM(line)-1, "PKSIGN %s", keyid);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (ctx->assuan_ctx, line,
                        membuf_data_cb, &data,
                        inq_needpin, &inqparm,
                        NULL, NULL);
  if (rc)
    goto out;

  /* Extract signature.  FIXME: can't we do this easier?  By reusing
     membuf, without another alloc/free? */

  sigbuf = get_membuf (&data, &sigbuflen);
  *r_buflen = sigbuflen;
  p = xtrymalloc (*r_buflen);
  *r_buf = (unsigned char*)p;
  if (!p)
    {
      rc = gpg_error_from_syserror ();
      goto out;
    }

  memcpy (p, sigbuf, sigbuflen);
  
 out:

  xfree (get_membuf (&data, &len));

  return rc;
}



/* CMD: READKEY.  */

/* Read a key with ID and return it in an allocate buffer pointed to
   by r_BUF as a valid S-expression. */
int
scd_readkey (scd_context_t ctx,
	     const char *id, gcry_sexp_t *key)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t buflen;
  unsigned char *buffer;

  *key = NULL;
  buffer = NULL;
  init_membuf (&data, 1024);

  /* Execute READKEY command.  */
  snprintf (line, DIM(line)-1, "READKEY %s", id);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (ctx->assuan_ctx, line,
                        membuf_data_cb, &data,
                        NULL, NULL,
                        NULL, NULL);
  if (rc)
    goto out;

  buffer = get_membuf (&data, &buflen);
  if (!buffer)
    {
      rc = gpg_error (GPG_ERR_ENOMEM);
      goto out;
    }

  if (!gcry_sexp_canon_len (buffer, buflen, NULL, NULL))
    {
      rc = gpg_error (GPG_ERR_INV_VALUE);
      *key = NULL;
    }
  else
    rc = gcry_sexp_new (key, buffer, buflen, 1);

 out:

  xfree (buffer);
    
  return rc;
}




/* Sends a GETINFO command for WHAT to the scdaemon through CTX.  The
   newly allocated result is stored in *RESULT.  Returns proper error
   code, zero on success.  */
int
scd_getinfo (scd_context_t ctx, const char *what, char **result)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  unsigned char *databuf;
  size_t datalen;
  char *res;

  *result = NULL;

  sprintf (line, "GETINFO %s", what);
  init_membuf (&data, 256);

  rc = assuan_transact (ctx->assuan_ctx, line, membuf_data_cb, &data,
			NULL, NULL, NULL, NULL);
  if (rc)
    goto out;

  databuf = get_membuf (&data, &datalen);
  if (databuf && datalen)
    {
      res = xtrymalloc (datalen + 1);
      if (!res)
	{
	  log_msg_error (ctx->loghandle,
			 _("warning: can't store getinfo data: %s"),
			 strerror (errno));
	  rc = gpg_error_from_syserror ();
	}
      else
	{
	  memcpy (res, databuf, datalen);
	  res[datalen] = 0;
	  *result = res;
	}
    }

 out:

  xfree (get_membuf (&data, &datalen));

  return rc;
}

/* END */
