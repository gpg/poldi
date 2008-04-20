/* support.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>

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
#include <assuan.h>

#include "util/support.h"
#include "util/defs.h"
#include <i18n.h>
#include "util/util.h"
#include "jnlib/stringhelp.h"
#include "jnlib/logging.h"
#include "auth-support/conv.h"

#include "getpin-cb.h"



static int
all_digitsp (const char *s)
{
  for (; *s && *s >= '0' && *s <= '9'; s++)
    ;
  return !*s;
}  


/* Query the user through PAM for his pin.  Display INFO to the user.
   Store the retrieved pin in PIN, which is of size PIN_SIZE.  If it
   does not fit, return error. */
static int
query_user (conv_t conv, const char *info, char *pin, size_t pin_size)
{
  char *buffer;
  int rc;

  buffer = NULL;
  rc = 0;

  while (1)			/* Loop until well-formed PIN retrieved. */
    {
      /* Retrieve PIN through PAM.  */
      rc = conv_ask (conv, 1, &buffer, info);
      if (rc)
	goto out;

      /* Do some basic checks on the entered PIN - shall we really
	 forbid to use non-digit characters in PIN? */
      if (strlen (buffer) < 6)	/* FIXME? is it really minimum of 6 bytes? */
	log_error ("invalid characters in PIN\n");
      else if (!all_digitsp (buffer))
	log_error ("invalid characters in PIN\n");
      else
	break;
    }

  /* FIXME: overflow possible? */

  if (strlen (buffer) >= pin_size)
    {
      log_error ("PIN too long for buffer!\n");
      rc = gpg_error (GPG_ERR_INV_DATA); /* ? */
      goto out;
    }

  strcpy (pin, buffer);

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
keypad_mode_enter (conv_t conv)
{
  int rc;

  rc = conv_tell (conv, "popup message start");

  return rc;
}

static int
keypad_mode_leave (conv_t conv)
{
  int rc;

  rc = conv_tell (conv, "popup message stop");

  return rc;
}

/* Callback used to ask for the PIN which should be set into BUF.  The
   buf has been allocated by the caller and is of size MAXBUF which
   includes the terminating null.  The function should return an UTF-8
   string with the passphrase, the buffer may optionally be padded
   with arbitrary characters.

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
  int rc;

#if 0
  /* FIXME: why "< 2"? -mo */
  if (buf && maxbuf < 2)
    return gpg_error (GPG_ERR_INV_VALUE);
#endif

  if (info && (info[0] == '|' && info[1] != '|'))
    {
      /* Weird that we received flags - they are neither expected nor
	 implemented here.  */
      log_error ("getpin_cb called with flags set in info string `%s'\n", info);
      goto out;
    }

  if (buf)
    rc = query_user (cb_data->conv, info, buf, maxbuf);
  else
    {
      /* Special handling for keypad mode hack. */

      /* If BUF has been passed as NULL, we are in keypad mode: the
	 callback notifies the user and immediately returns.  */
      if (maxbuf == 0) /* Close the pinentry. */
	rc = keypad_mode_leave (cb_data->conv);
      else if (maxbuf == 1)  /* Open the pinentry. */
	rc = keypad_mode_enter (cb_data->conv);
      else
        rc = gpg_error (GPG_ERR_INV_VALUE); /* FIXME: must signal
					       internal error(!)
					       -mo */
    }

 out:

  return rc;
}

/* END */
