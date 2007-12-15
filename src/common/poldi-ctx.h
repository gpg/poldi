/* poldi-ctx.h - defines poldi context structure
   Copyright (C) 2007 g10 Code GmbH
 
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

#include <config.h>

#include <security/pam_modules.h>

#include "scd/scd.h"
#ifdef ENABLE_AUTH_METHOD_X509
# include "dirmngr/dirmngr.h"
#endif

#include "poldi-ctx-opaque.h"

struct poldi_ctx_s
{
  /* Options. */
  char *logfile;
  unsigned int auth_method;
  unsigned int wait_timeout;
 char *dirmngr_socket;
  
  int debug;

  /* Scdaemon. */
  scd_context_t scd;

#ifdef ENABLE_AUTH_METHOD_X509
  /* Dirmngr. */
   dirmngr_ctx_t dirmngr;
#endif

  pam_handle_t *pam_handle;
  const struct pam_conv *pam_conv;
};

#endif
