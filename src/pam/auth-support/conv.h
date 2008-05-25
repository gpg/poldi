/* conv.h - PAM conversation abstraction for Poldi.
   Copyright (C) 2007, 2008 g10 Code GmbH
 
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
 
#ifndef POLDI_CONV_H
#define POLDI_CONV_H

#include <gpg-error.h>
#include <stdarg.h>

#define PAM_SM_AUTH
#include <security/pam_modules.h>

struct conv_s;

typedef struct conv_s *conv_t;

/* Create a new PAM conversation object based in PAM_CONV and store it
   in *CONV.  Returns proper error code. */
gpg_error_t conv_create (conv_t *conv, const struct pam_conv *pam_conv);

/* Destroy the conv object CONV.  */
void conv_destroy (conv_t conv);

/* Pass the (format string) message FMT to the PAM user through the
   PAM Poldi context CTX.  Return proper error code.  */
gpg_error_t conv_tell (conv_t conv, const char *fmt, ...);

/* Use the PAM Poldi context CTX to pass the (format string) message
   FMT to the PAM user and query for a response, which is to be stored
   in *RESPONSE (newly allocated).  Depending on the boolean value
   ASK_SECRET, a secret response is queried (e.g. PIN).  Returns
   proper error code.  */
gpg_error_t conv_ask (conv_t conv, int ask_secret, char **response,
		      const char *fmt, ...);

#endif
