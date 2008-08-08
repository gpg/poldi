/* wait-for-card.h - Waiting for smartcard insertion (Poldi)
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
