/* wait-for-card.c - Implement waiting for smartcard insertion for Poldi
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
#include <time.h>
#include "scd-support.h"
#include <scd/scd.h>



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

  if (timeout)
    time (&t0);

  err = (*conv) (CONVERSATION_TELL, opaque, "Insert card ...", NULL);
  if (err)
    /* FIXME.  <- ? */
    goto out;

  while (1)
    {
      err = scd_serialno (ctx, NULL);

      if (err == 0)
	/* Card present!  */
	break;
      else if (gpg_err_code (err) == GPG_ERR_CARD_NOT_PRESENT)

	{
	  /* Card not present.  */

	  /* FIXME: are there error codes besides
	     GPG_ERR_CARD_NOT_PRESENT, which can be thrown in case a
	     smartcard is not currently inserted?  */

#ifdef HAVE_NANOSLEEP      
	  {
	    /* Wait 500ms.  */
	    struct timespec augenblick;

	    augenblick.tv_sec = 0;
	    augenblick.tv_nsec = 500000000;
	    nanosleep (&augenblick, NULL);
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
      else
	/* Unexpected different error -> stop waiting and propagate
	   error upwards.  */
	break;
    }

 out:

  return err;
}
