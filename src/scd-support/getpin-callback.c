/* support.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2007 g10 Code GmbH
 
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

#include <scd-support.h>

#include <common/support.h>
#include <common/defs.h>

#include <jnlib/stringhelp.h>
#include <jnlib/xmalloc.h>
#include <jnlib/logging.h>

#include <assuan.h>
#include <i18n.h>
#include "util.h"



struct pin_entry_info_s 
{
  int min_digits; /* min. number of digits required or 0 for freeform entry */
  int max_digits; /* max. number of allowed digits allowed*/
  int max_tries;
  int failed_tries;
  const char *cb_errtext; /* used by the cb to displaye a specific error */
  size_t max_length; /* allocated length of the buffer */
  char pin[1];
};



static int
all_digitsp( const char *s)
{
  for (; *s && *s >= '0' && *s <= '9'; s++)
    ;
  return !*s;
}  


/* Call the Entry and ask for the PIN.  We do check for a valid PIN
   number here and repeat it as long as we have invalid formed
   numbers. */
/* FIXME: pin length, cecks, looping, etc, all... -mo  */
int
agent_askpin (struct pin_querying_parm *parm,
              const char *desc_text, const char *prompt_text,
              const char *initial_errtext,
              struct pin_entry_info_s *pininfo)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  const char *errtext = NULL;
  char *PIN;

  PIN = NULL;

  if (!pininfo || pininfo->max_length < 1)
    return gpg_error (GPG_ERR_INV_VALUE);
  if (!desc_text && pininfo->min_digits)
    desc_text = _("Please enter your PIN, so that the secret key "
                  "can be unlocked for this session");
  else if (!desc_text)
    desc_text = _("Please enter your passphrase, so that the secret key "
                  "can be unlocked for this session");

  for (;pininfo->failed_tries < pininfo->max_tries; pininfo->failed_tries++)
    {
      if (errtext)
        { 
          /* TRANLATORS: The string is appended to an error message in
             the pinentry.  The %s is the actual error message, the
             two %d give the current and maximum number of tries. */

	  /* FIXME, moritz, we can probably eliminate the use of
	     ASSUAN_LINE_LENGTH here.  */
          snprintf (line, DIM(line)-1, _("%s (try %d of %d)"),
                    errtext, pininfo->failed_tries+1, pininfo->max_tries);
	  line[DIM(line)-1] = 0;

	  rc = (*parm->conv) (CONVERSATION_TELL, parm->conv_opaque,
			      line, NULL);
          if (rc)
	    goto out;
	  //            return unlock_pinentry (rc);
          errtext = NULL;
        }

      rc = (*parm->conv) (CONVERSATION_ASK_SECRET, parm->conv_opaque,
			  "GETPIN", &PIN);
      if (! rc)
	{
	  if (strlen (PIN) >= pininfo->max_length)
	    {
	      /* FIXME, error code -mo. */
	      rc = gpg_error (GPG_ERR_INV_VALUE);
	      errtext = _("PIN too long");
	      /* FIXME: after this choice, we shouldn't goto out!  */
	    }
	  else
	    strcpy (pininfo->pin, PIN);
	}
      if (rc)
	goto out;

      if (!errtext && pininfo->min_digits)
        {
          /* do some basic checks on the entered PIN. */
          if (!all_digitsp (pininfo->pin))
            errtext = _("Invalid characters in PIN");
          else if (pininfo->max_digits
                   && strlen (pininfo->pin) > pininfo->max_digits)
            errtext = _("PIN too long");
          else if (strlen (pininfo->pin) < pininfo->min_digits)
            errtext = _("PIN too short");
        }

      if (!errtext)
	break;
    }

 out:

  return rc;
}

/* Pop up a message window similar to the confirm one but keep it open
   until agent_popup_message_stop has been called.  It is crucial for
   the caller to make sure that the stop function gets called as soon
   as the message is not anymore required because the message is
   system modal and all other attempts to use the pinentry will fail
   (after a timeout). */
int 
agent_popup_message_start (struct pin_querying_parm *parm,
			   const char *desc, const char *ok_btn)
{
  int rc;

  rc = (*parm->conv) (CONVERSATION_TELL, parm->conv_opaque, desc, NULL);

  return rc;
}

/* Close a popup window. */
void
agent_popup_message_stop (struct pin_querying_parm *parm)
{
  /* FIXME: error handling? -mo  */

  (*parm->conv) (CONVERSATION_TELL, parm->conv_opaque, "popup message stop", NULL);
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

   Flags:

      'N' = New PIN, this requests a second prompt to repeat the the
            PIN.  If the PIN is not correctly repeated it starts from
            all over.
      'A' = The PIN is an Admin PIN, SO-PIN, PUK or alike.

   Example:

     "|AN|Please enter the new security officer's PIN"
     
   The text "Please ..." will get displayed and the flags 'A' and 'N'
   are considered.
 */
int 
getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf)
{
  struct pin_entry_info_s *pi;
  int rc;
  struct pin_querying_parm *parm = opaque;
  const char *ends, *s;
  int any_flags = 0;
  int newpin = 0;
  const char *again_text = NULL;
  const char *prompt = "PIN";

  if (buf && maxbuf < 2)
    return gpg_error (GPG_ERR_INV_VALUE);

  /* Parse the flags. */
  if (info && *info =='|' && (ends=strchr (info+1, '|')))
    {
      for (s=info+1; s < ends; s++)
        {
          if (*s == 'A')
            prompt = _("Admin PIN");
          else if (*s == 'N')
            newpin = 1;
        }
      info = ends+1;
      any_flags = 1;
    }
  else if (info && *info == '|')
    log_debug ("pin_cb called without proper PIN info hack\n");

  /* If BUF has been passed as NULL, we are in keypad mode: The
     callback opens the popup and immediatley returns. */
  if (!buf)
    {
      if (maxbuf == 0) /* Close the pinentry. */
        {
          agent_popup_message_stop (parm);
          rc = 0;
        }
      else if (maxbuf == 1)  /* Open the pinentry. */
        {
          rc = agent_popup_message_start (parm, info, NULL);
        }
      else
        rc = gpg_error (GPG_ERR_INV_VALUE);
      return rc;
    }

  /* FIXME: keep PI and TRIES in OPAQUE.  Frankly this is a whole
     mess because we should call the card's verify function from the
     pinentry check pin CB. */
 again:
  pi = gcry_calloc_secure (1, sizeof (*pi) + maxbuf + 10);
  if (!pi)
    return gpg_error_from_syserror ();
  pi->max_length = maxbuf-1;
  pi->min_digits = 0;  /* we want a real passphrase */
  pi->max_digits = 8;
  pi->max_tries = 3;

  if (any_flags)
    {
      rc = agent_askpin (parm, info, prompt, again_text, pi);
      again_text = NULL;
      if (!rc && newpin)
        {
          struct pin_entry_info_s *pi2;
          pi2 = gcry_calloc_secure (1, sizeof (*pi) + maxbuf + 10);
          if (!pi2)
            {
              rc = gpg_error_from_syserror ();
              xfree (pi);
              return rc;
            }
          pi2->max_length = maxbuf-1;
          pi2->min_digits = 0;
          pi2->max_digits = 8;
          pi2->max_tries = 1;
          rc = agent_askpin (parm, _("Repeat this PIN"), prompt, NULL, pi2);
          if (!rc && strcmp (pi->pin, pi2->pin))
            {
              again_text = N_("PIN not correctly repeated; try again");
              xfree (pi2);
              xfree (pi);
              goto again;
            }
          xfree (pi2);
        }
    }
  else
    {
      char *desc;
      if ( asprintf (&desc,
                     _("Please enter the PIN%s%s%s to unlock the card"), 
                     info? " (`":"",
                     info? info:"",
                     info? "')":"") < 0)
        desc = NULL;
      rc = agent_askpin (parm, desc?desc:info, prompt, NULL, pi);
      free (desc);
    }

  if (!rc)
    {
      strncpy (buf, pi->pin, maxbuf-1);
      buf[maxbuf-1] = 0;
    }
  xfree (pi);
  return rc;
}

/* END */
