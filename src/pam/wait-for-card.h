#ifndef WAIT_FOR_CARD_H
#define WAIT_FOR_CARD_H

#include <gpg-error.h>
#include "common/poldi-ctx-opaque.h"

/* Wait for insertion of a card in slot specified by SLOT,
   communication with the user through the PAM conversation function
   CONV.  If REQUIRE_CARD_SWITCH is TRUE, require a card switch.

   Returns proper error code.  */
gpg_error_t wait_for_card (poldi_ctx_t ctx, unsigned int timeout);

#endif
