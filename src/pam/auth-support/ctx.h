/* ctx.h - Poldi context structure.
   Copyright (C) 2008 g10 Code GmbH
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef POLDI_CTX_H
#define POLDI_CTX_H

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include "scd/scd.h"
#include "auth-support/conv.h"

/* FIXME: describe rational behind this mechanism.  */

struct poldi_ctx_s
{
  /* Options. */
  char *logfile;
  int auth_method;
  void *cookie;

  int debug;

  /* Scdaemon. */
  scd_context_t scd;

  pam_handle_t *pam_handle;

  conv_t conv;

  /* PAM username.  */
  const char *username;

  struct scd_cardinfo cardinfo;  
};

typedef struct poldi_ctx_s *poldi_ctx_t;

#endif
