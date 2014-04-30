/* getpin-cb.c - getpin Assuan Callback (Poldi)
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 
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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>
#include <pwd.h>
#include <dirent.h>
#include <time.h>

#include <gcrypt.h>

#include "assuan.h"
#include "util/support.h"
#include <util/defs.h>
#include "util/util.h"
#include "util/simplelog.h"
#include "auth-support/conv.h"

#include "ctx.h"

#include "getpin-cb.h"



/* Returns TRUE if the string S contains only decimal digits, FALSE
   otherwise. */
static int
all_digitsp (const char *s)
{
  for (; *s && *s >= '0' && *s <= '9'; s++)
    ;
  return !*s;
}  

/* Query the user through PAM for his PIN.  Display INFO to the user.
   Store the retrieved pin in PIN, which is of size PIN_SIZE.  If it
   does not fit, return error. */
static int
query_user (poldi_ctx_t ctx, const char *info, char *pin, size_t pin_size)
{
  char *buffer;
  int rc;

  buffer = NULL;
  rc = 0;

  while (1)			/* Loop until well-formed PIN retrieved. */
    {
      /* Retrieve PIN through PAM.  */
      rc = conv_ask (ctx->conv, 1, &buffer, info);
      if (rc)
	goto out;

      /* Do some basic checks on the entered PIN. FIXME: hard-coded
	 values! Is this really the correct place for these checks?
	 Shouldn't they be done in scdaemon itself?  -mo */

      if (strlen (buffer) < 6)	/* FIXME? is it really minimum of 6 bytes? */
	{
	  log_msg_error (ctx->loghandle, _("PIN too short"));
	  conv_tell (ctx->conv, "%s", _("PIN too short"));
	}
      else
	break;
    }

  if (strlen (buffer) >= pin_size)
    {
      log_msg_error (ctx->loghandle, _("PIN too long for buffer!"));
      rc = gpg_error (GPG_ERR_INV_DATA); /* ? */
      goto out;
    }

  strncpy (pin, buffer, pin_size - 1);
  pin[pin_size-1] = 0;

 out:

  return rc;
}

/* Pop up a message window similar to the confirm one but keep it open
   until agent_popup_message_stop has been called.  It is crucial for
   the caller to make sure that the stop function gets called as soon
   as the message is not anymore required because the message is
   system modal and all other attempts to use the pinentry will fail
   (after a timeout). */
static int
keypad_mode_enter (poldi_ctx_t ctx, const char *info)
{
  int rc;

  rc = conv_tell (ctx->conv, info);

  return rc;
}

static int
keypad_mode_leave (poldi_ctx_t ctx)
{
  return 0;
}

/* This function is taken from pinentry.c.  */
/* Note, that it is sufficient to allocate the target string D as
   long as the source string S, i.e.: strlen(s)+1; */
static void
strcpy_escaped (char *d, const unsigned char *s)
{
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        { 
          s++;
          *d++ = xtoi_2 ( s);
          s += 2;
        }
      else
        *d++ = *s++;
    }
  *d = 0; 
}

/* Unescape special characters in INFO and write unescaped string into
   newly allocated memory in *INFO_FROBBED.  Returns proper error
   code.  */
static gpg_error_t
frob_info_msg (const char *info, char **info_frobbed)
{
  gpg_error_t err = 0;

  *info_frobbed = xtrymalloc (strlen (info) + 1);
  if (!*info_frobbed)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  strcpy_escaped (*info_frobbed, info);

 out:

  return err;
}

/* Callback used to ask for the PIN which shall be written into BUF.
   The buf has been allocated by the caller and is of size MAXBUF
   which includes the terminating null.  The function should return an
   UTF-8 string with the passphrase/PIN, the buffer may optionally be
   padded with arbitrary characters.

   INFO gets displayed as part of a generic string.  However if the
   first character of INFO is a vertical bar all up to the next
   verical bar are considered flags and only everything after the
   second vertical bar gets displayed as the full prompt.

   We don't need/implement the N/A flags.  When they occur, we signal
   an error.  */
int 
getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf)
{
  struct getpin_cb_data *cb_data = opaque;
  poldi_ctx_t ctx = cb_data->poldi_ctx;
  char *info_frobbed;
  int err;

  info_frobbed = NULL;
  err = 0;

#if 0
  /* FIXME: why "< 2"? -mo */
  if (buf && maxbuf < 2)
    return gpg_error (GPG_ERR_INV_VALUE);
#endif

  /* Older SCDaemons simply send "PIN" as prompt. We do not process
     this prompt here but use a special case later. */
  if (info && (strcmp (info, "PIN") != 0))
    {
      if (info[0] == '|')
	{
	  if (info[1] == '|')
	    /* Skip "||" at the beginning.  */
	    info += 2;
	  else
	    {
	      /* Weird that we received flags - they are neither expected nor
		 implemented here.  */
	      log_msg_error (ctx->loghandle,
			     _("getpin_cb called with flags set in info string `%s'\n"),
			     info);
	      err = gpg_error (GPG_ERR_INV_VALUE); /* FIXME? */
	      goto out;
	    }
	}
      err = frob_info_msg (info, &info_frobbed);
      if (err)
	{
	  log_msg_error (ctx->loghandle,
			 _("frob_info_msg failed for info msg of size %u\n"),
			 (unsigned int) strlen (info));
	  goto out;
	}
    }

  if (buf)
    {
      /* BUF being non-zero means we are not using a keypad.  */

      if (info_frobbed)
	err = query_user (ctx, info_frobbed, buf, maxbuf);
      else
	/* Use string which is more user friendly. */
	err = query_user (ctx, _("Please enter the PIN:"), buf, maxbuf);
    }
  else
    {
      /* Special handling for keypad mode hack. */

      /* If BUF has been passed as NULL, we are in keypad mode: the
	 callback notifies the user and immediately returns.  */
      if (maxbuf == 0)
	{
	  /* Close the "pinentry". */
	  err = keypad_mode_leave (ctx);
	}
      else if (maxbuf == 1)
	{
	  /* Open the "pinentry". */
	  if (info_frobbed)
	    err = keypad_mode_enter (ctx, info_frobbed);
	  else
	    err = keypad_mode_enter (ctx, _("Please enter the PIN:"));
	}
      else
        err = gpg_error (GPG_ERR_INV_VALUE); /* FIXME: must signal
						internal error(!)?
						-mo */
    }

 out:

  xfree (info_frobbed);

  return err;
}

/* END */
