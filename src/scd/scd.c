/* call-scd.c - Interface to Scdaemon
 *	Copyright (C) 2001, 2002, 2005 Free Software Foundation, Inc.
 *	Copyright (C) 2007 g10code GmbH. 
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <config.h>
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
#ifndef HAVE_W32_SYSTEM
#include <sys/wait.h>
#endif

#include "scd.h"
#include <assuan.h>
#include <gpg-error.h>
#include <gcrypt.h>
#include "../common/util.h"
//#include "../common/errors.h"
#include "membuf.h"
#include "i18n.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif



struct scd_context
{
  assuan_context_t assuan_ctx;
  unsigned int flags;
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
  assuan_context_t ctx;
  int (*getpin_cb)(void *, const char *, char*, size_t);
  void *getpin_cb_arg;
};


/* Local prototypes.  */
static assuan_error_t membuf_data_cb (void *opaque,
                                      const void *buffer, size_t length);





int
scd_disconnect (scd_context_t scd_ctx)
{
  if (scd_ctx)
    {
      assuan_disconnect (scd_ctx->assuan_ctx);
      xfree (scd_ctx);
    }

  return 0;
}

static int
agent_connect_from_infostr (const char *agent_infostr,
			    assuan_context_t *agent_ctx)
{
  char *infostr;
  int prot;
  int pid;
  int rc;
  char *p;

  infostr = xstrdup (agent_infostr);
  *agent_ctx = NULL;
  rc = 0;

  if ( !(p = strchr (infostr, ':')) || p == infostr)
    {
      log_error (_("malformed GPG_AGENT_INFO environment variable\n"));
      /* moritz: fixme, wrong err code.  */
      rc = gpg_error (GPG_ERR_ASS_CONNECT_FAILED);
      goto out;
    }
  *p++ = 0;
  pid = atoi (p);
  while (*p && *p != ':')
    p++;
  prot = *p? atoi (p+1) : 0;
  if (prot != 1)
    {
      log_error (_("agent protocol version %d is not supported\n"),	/* FIXME,
									   moritz?  */
		 prot);
      /* moritz: fixme, wrong err code.  */
      rc = gpg_error (GPG_ERR_ASS_CONNECT_FAILED);
      goto out;
    
    }

  /* Connect!  */
  rc = assuan_socket_connect (agent_ctx, infostr, pid);

 out:

  xfree (infostr);

  return rc;
}

static int
agent_scd_getinfo_socket_name (assuan_context_t ctx, char **socket_name)
{
  unsigned char *databuf;
  size_t datalen;
  membuf_t data;
  char *res;
  int rc;

  init_membuf (&data, 256);
  *socket_name = NULL;
  res = NULL;
  rc = 0;

  rc = assuan_transact (ctx, "SCD GETINFO socket_name", membuf_data_cb, &data,
			NULL, NULL, NULL, NULL);
  if (rc)
    goto out;

  databuf = get_membuf (&data, &datalen);
  if (databuf && datalen)
    {
      res = xtrymalloc (datalen + 1);
      if (!res)
	{
	  log_error ("warning: can't store getinfo data: %s\n",
		     strerror (errno));
	  rc = gpg_error_from_syserror ();
	}
      else
	{
	  memcpy (res, databuf, datalen);
	  res[datalen] = 0;
	  *socket_name = res;
	}
    }

 out:

  xfree (get_membuf (&data, &datalen));

  return rc;
}


static int
get_scd_socket_from_agent (const char *agent_infostr, char **socket_name)
{
  assuan_context_t ctx;
  int rc;

  *socket_name = NULL;
  ctx = NULL;
  rc = 0;

  rc = agent_connect_from_infostr (agent_infostr, &ctx);
  if (rc)
    goto out;

  rc = agent_scd_getinfo_socket_name (ctx, socket_name);

 out:

  assuan_disconnect (ctx);

  return rc;
}



/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Handle the server's initial greeting */
int
scd_connect (scd_context_t *scd_ctx,
	     const char *agent_infostr,
	     const char *scd_path,
	     unsigned int flags)
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

  if (!agent_infostr || !*agent_infostr)
    {
      /* Start new scdaemon.  */

      const char *pgmname;
      const char *argv[3];
      int no_close_list[3];
      int i;

      if (flags & SCD_FLAG_VERBOSE)
        log_info (_("no running scdaemon - starting one\n"));

      if (fflush (NULL))
        {
          rc = gpg_error_from_syserror ();
          log_error ("error flushing pending output: %s\n", strerror (errno));
	  goto out;
        }

      if (!scd_path || !*scd_path)
        scd_path = GNUPG_DEFAULT_SCD;
      if ( !(pgmname = strrchr (scd_path, '/')))
        pgmname = scd_path;
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

      /* connect to the agent and perform initial handshaking */
      rc = assuan_pipe_connect (&assuan_ctx, scd_path, argv,
                                no_close_list);
    }
  else
    {
      /* Try to connect to agent and receive scdaemon socket name
	 through agent.  */

      char *scd_socket;

      rc = get_scd_socket_from_agent (agent_infostr, &scd_socket);
      if (! rc)
	rc = assuan_socket_connect (&assuan_ctx, scd_socket, 0);

      xfree (scd_socket);
    }

  if (rc)
    {
      log_error ("can't connect to the agent: %s\n", gpg_strerror (rc));
      goto out;
    }

  // FIXME: not necessary? -moritz
  rc = assuan_transact (assuan_ctx, "RESTART", NULL, NULL, NULL, NULL, NULL,NULL);

 out:

  if (rc)
    {
      assuan_disconnect (assuan_ctx);
      xfree (ctx);

    }
  else
    {
      ctx->assuan_ctx = assuan_ctx;
      ctx->flags = flags;
      *scd_ctx = ctx;
      if (flags & SCD_FLAG_VERBOSE)
	log_debug ("connection to scdaemon established\n");
    }

  return rc;
}





/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary Nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *
unescape_status_string (const unsigned char *s)
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
static struct scd_cardinfo cardinfo_NULL;


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

int
scd_learn (scd_context_t ctx,
	   struct scd_cardinfo *cardinfo)
{
  int rc;

  *cardinfo = cardinfo_NULL;
  rc = assuan_transact (ctx->assuan_ctx, "LEARN --force",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, cardinfo);

  return rc;
}

void
scd_release_cardinfo (struct scd_cardinfo *info)
{
  if (!info)
    return;

  xfree (info->serialno); info->serialno = NULL;
  xfree (info->disp_name); info->disp_name = NULL;
  xfree (info->login_data); info->login_data = NULL;
  info->fpr1valid = info->fpr2valid = info->fpr3valid = 0;
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
        return out_of_core ();
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }
  
  return 0;
}

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
int
scd_serialno (scd_context_t ctx, char **r_serialno)
{
  char *serialno;
  int rc;

  serialno = NULL;

  rc = assuan_transact (ctx->assuan_ctx, "SERIALNO",
                        NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  *r_serialno = serialno;

  if (rc)
    xfree (serialno);

  return rc;
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

  if (!strncmp (line, "NEEDPIN", 7) && (line[7] == ' ' || !line[7]))
    {
      line += 7;
      while (*line == ' ')
        line++;
      
      pinlen = 90;
      pin = gcry_malloc_secure (pinlen);
      if (!pin)
        return out_of_core ();

      rc = parm->getpin_cb (parm->getpin_cb_arg, line, pin, pinlen);
      if (!rc)
        rc = assuan_send_data (parm->ctx, pin, pinlen);
      xfree (pin);
    }
  else if (!strncmp (line, "POPUPKEYPADPROMPT", 17)
           && (line[17] == ' ' || !line[17]))
    {
      line += 17;
      while (*line == ' ')
        line++;
      
      rc = parm->getpin_cb (parm->getpin_cb_arg, line, NULL, 1);
    }
  else if (!strncmp (line, "DISMISSKEYPADPROMPT", 19)
           && (line[19] == ' ' || !line[19]))
    {
      rc = parm->getpin_cb (parm->getpin_cb_arg, "", NULL, 0);
    }
  else
    {
      log_error ("unsupported inquiry `%s'\n", line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

  return rc;
}



/* Create a signature using the current card */
int
scd_pksign (scd_context_t ctx,
	    const char *keyid,
	    int (*getpin_cb)(void *, const char *, char*, size_t),
	    void *getpin_cb_arg,
	    const unsigned char *indata, size_t indatalen,
	    unsigned char **r_buf, size_t *r_buflen)
{
  int rc, i;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_s inqparm;
  size_t len;
  unsigned char *sigbuf;
  size_t sigbuflen;

  *r_buf = NULL;
  init_membuf (&data, 1024);

  if (indatalen*2 + 50 > DIM(line))
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      goto out;
    }

  /* Inform scdaemon about the data to be signed. */

  sprintf (line, "SETDATA ");
  p = line + strlen (line);
  for (i=0; i < indatalen ; i++, p += 2 )
    sprintf (p, "%02X", indata[i]);
  rc = assuan_transact (ctx->assuan_ctx, line,
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    goto out;

  /* Setup NEEDPIN inquiry handler.  */

  inqparm.ctx = ctx->assuan_ctx;
  inqparm.getpin_cb = getpin_cb;
  inqparm.getpin_cb_arg = getpin_cb_arg;

  /* Go, sign it. */
  snprintf (line, DIM(line)-1, "PKSIGN %s", keyid);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (ctx->assuan_ctx, line,
                        membuf_data_cb, &data,
                        inq_needpin, &inqparm,
                        NULL, NULL);
  if (rc)
    goto out;

  /* Extract signature. */

  sigbuf = get_membuf (&data, &sigbuflen);

#if 0
  /* Create an S-expression from it which is formatted like this:
     "(7:sig-val(3:rsa(1:sSIGBUFLEN:SIGBUF)))" */
  *r_buflen = 21 + 11 + sigbuflen + 4;
  p = xtrymalloc (*r_buflen);
  *r_buf = (unsigned char*)p;
  if (!p)
    {
      rc = gpg_error_from_syserror ();
      goto out;
    }

  p = stpcpy (p, "(7:sig-val(3:rsa(1:s" );
  sprintf (p, "%u:", (unsigned int)sigbuflen);
  p += strlen (p);
  memcpy (p, sigbuf, sigbuflen);
  p += sigbuflen;
  strcpy (p, ")))");
#else
  /* Create an S-expression from it which is formatted like this:
     "(7:sig-val(3:rsa(1:sSIGBUFLEN:SIGBUF)))" */
  *r_buflen = sigbuflen;
  p = xtrymalloc (*r_buflen);
  *r_buf = (unsigned char*)p;
  if (!p)
    {
      rc = gpg_error_from_syserror ();
      goto out;
    }

  memcpy (p, sigbuf, sigbuflen);
#endif
  
 out:

  xfree (get_membuf (&data, &len));

#if 0
  if (! rc)
    assert (gcry_sexp_canon_len (*r_buf, *r_buflen, NULL, NULL));
#endif

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
  size_t len, buflen;
  unsigned char *buffer;

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


#if 0

/* FIXME, moritz, might be useful for Poldi.  */

/* Type used with the card_getattr_cb.  */
struct card_getattr_parm_s {
  const char *keyword;  /* Keyword to look for.  */
  size_t keywordlen;    /* strlen of KEYWORD.  */
  char *data;           /* Malloced and unescaped data.  */
  int error;            /* ERRNO value or 0 on success. */
};

/* Callback function for agent_card_getattr.  */
static assuan_error_t
card_getattr_cb (void *opaque, const char *line)
{
  struct card_getattr_parm_s *parm = opaque;
  const char *keyword = line;
  int keywordlen;

  if (parm->data)
    return 0; /* We want only the first occurrence.  */

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == parm->keywordlen
      && !memcmp (keyword, parm->keyword, keywordlen))
    {
      parm->data = unescape_status_string ((const unsigned char*)line);
      if (!parm->data)
        parm->error = errno;
    }
  
  return 0;
}


/* Call the agent to retrieve a single line data object. On success
   the object is malloced and stored at RESULT; it is guaranteed that
   NULL is never stored in this case.  On error an error code is
   returned and NULL stored at RESULT. */
gpg_error_t
agent_card_getattr (ctrl_t ctrl, const char *name, char **result)
{
  int err;
  struct card_getattr_parm_s parm;
  char line[ASSUAN_LINELENGTH];

  *result = NULL;

  if (!*name)
    return gpg_error (GPG_ERR_INV_VALUE);

  memset (&parm, 0, sizeof parm);
  parm.keyword = name;
  parm.keywordlen = strlen (name);

  /* We assume that NAME does not need escaping. */
  if (8 + strlen (name) > DIM(line)-1)
    return gpg_error (GPG_ERR_TOO_LARGE);
  stpcpy (stpcpy (line, "GETATTR "), name); 

  err = start_scd (ctrl);
  if (err)
    return err;

  err = assuan_transact (ctrl->scd_local->ctx, line,
                         NULL, NULL, NULL, NULL,
                         card_getattr_cb, &parm);
  if (!err && parm.error)
    err = gpg_error_from_errno (parm.error);
  
  if (!err && !parm.data)
    err = gpg_error (GPG_ERR_NO_DATA);
  
  if (!err)
    *result = parm.data;
  else
    xfree (parm.data);

  return unlock_scd (ctrl, err);
}

#endif



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
	  log_error ("warning: can't store getinfo data: %s\n",
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

/* Reset the SCD if it has been used.  */
int
scd_reset (scd_context_t ctx)
{
  int rc;

  assuan_transact (ctx->assuan_ctx, "RESTART",
		   NULL, NULL, NULL, NULL, NULL, NULL);

  return 0;
}



/* END */
