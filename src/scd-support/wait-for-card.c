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

#include <gpg-error.h>

//#include <stdio.h>
//#include <stdlib.h>
//#include <assert.h>
//#include <unistd.h>
//#include <fcntl.h>
//#include <sys/stat.h>
//#include <errno.h>
//#include <stdarg.h>
//#include <pwd.h>
//#include <dirent.h>
#include <time.h>

//#include <gcrypt.h>

#include "support.h"

#include <scd/scd.h>

//#include <jnlib/stringhelp.h>
//#include <jnlib/xmalloc.h>
//#include <jnlib/logging.h>

//#include <agent/call-agent.h>
//#include <i18n.h>
//#include "util.h"

/* Wait for insertion of a card in slot specified by SLOT,
   communication with the user through the PAM conversation function
   CONV.  If REQUIRE_CARD_SWITCH is TRUE, require a card switch.

   Returns proper error code.  */
gpg_error_t
wait_for_card (scd_context_t ctx,
	       unsigned int timeout, conversation_cb_t conv, void *opaque)
{
  gpg_error_t err;		/* <- rc?  */
  time_t t0;
  time_t t;
  char *getinfo_result;
  int card_usable;

  if (timeout)
    time (&t0);

  err = (*conv) (CONVERSATION_TELL, opaque, "Insert card ...", NULL);
  if (err)
    /* FIXME.  <- ? */
    goto out;

  while (1)
    {
      /* FIXME? */
      err = scd_getinfo (ctx, "status", &getinfo_result);
      //err = agent_learn (&cardinfo);
      //if (! err)
      //	{
      //	  if (serialno)
      //	    *serialno = xstrdup (cardinfo.serialno);
      //	  if (fingerprint)
      //	    *fingerprint = xstrdup (cardinfo.fpr3);
      //	  if (card_version)
      //	    *card_version = 0;	/* FIXME!! */
      //	  agent_release_card_info (&cardinfo);
      //	  break;
      //	}
      if (err)
	break;

      card_usable = (getinfo_result[0] == 'u');
      free (getinfo_result);	/* FIXME, i guess we need xfree?
				   check! */

      if (card_usable)
	break;
      
      
#ifdef HAVE_NANOSLEEP      
      {
        struct timespec t;

        t.tv_sec = 0;
        t.tv_nsec = 300000000;
        nanosleep (&t, NULL);  /* Wait 300ms.  */
      }
#else
      sleep (1);
#endif

      if (timeout)
	{
	  time (&t);
	  if ((t - t0) > timeout)
	    {
	      err = GPG_ERR_CARD_NOT_PRESENT;
	      break;
	    }
	}
    }

 out:

  return err;
}
