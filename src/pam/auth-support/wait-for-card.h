#ifndef WAIT_FOR_CARD_H
#define WAIT_FOR_CARD_H

#include <gpg-error.h>

#include "scd/scd.h"

/* Wait for insertion of a card in slot specified by SLOT,
   communication with the user through the PAM conversation function
   CONV.

   Returns proper error code.  */
gpg_error_t wait_for_card (scd_context_t ctx, unsigned int timeout);

#endif
