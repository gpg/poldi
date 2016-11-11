/* ctx.h - Poldi context structure.
   Copyright (C) 2008, 2009 g10 Code GmbH
 
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
 
#ifndef POLDI_CTX_H
#define POLDI_CTX_H

#define PAM_SM_AUTH
#include <security/pam_modules.h>

#include <util/simplelog.h>
#include <util/simpleparse.h>

#include "scd/scd.h"
#include "auth-support/conv.h"

/* We use a "context" object in Poldi, since a PAM Module should not
   contain static variables.  (In theory) this allows for a
   multithreaded application to authenticate users concurrently.

   There are certain objects which are to be accessed by many
   functions contained in Poldi, like: debug flag, pam_handle, scd,
   logging stream, etc.

   So we have two choices: either these variables are globally visible
   or they are allocated in pam_sm_authenticate() and passed down to
   each function. For the above mentioned reasons, solution one is not
   applicable for a PAM module.  Therefore we need go down route two.
   But surely we do not want to pass each and every of the useful
   variables down to every function, thus we encapsulate everything
   which might be useful to other functions in a context object.
   Then, this context object (allocated and dealloacted in
   pam_sm_authenticate) is passed down.
 */

struct poldi_ctx_s
{
  /* Options. */

  char *logfile;
  log_handle_t loghandle;	/* Our handle for simplelog.  */
  simpleparse_handle_t parsehandle; /* Handle for simpleparse.  */
  int auth_method;		/* The ID of the authentication method
				   in use.  */
  void *cookie;			/* Cookie for authentication
				   method. */

  int debug;			/* Debug flag.  If true, functions
				   should emmit debugging
				   messages.  */
  int modify_environment;	/* Set Poldi-related variables in the
				   PAM environment.  */
  int quiet;			/* Be more quiet during PAM
				   conversation with user. */
  int use_agent;		/* Use gpg-agent to connect scdaemon.  */

  /* Scdaemon. */
  char *scdaemon_program;	/* Path of Scdaemon program to execute.  */
  char *scdaemon_options;	/* Path of Scdaemon configuration file.  */
  scd_context_t scd;		/* Handle for the Scdaemon access
				   layer.  */

  pam_handle_t *pam_handle;	/* PAM handle. */

  conv_t conv;			/* Handle for the conv(ersation)
				   subsystem.  */

  /* PAM username.  */
  const char *username;		/* Username retrieved by PAM.  */

  struct scd_cardinfo cardinfo;	/* Smartcard information
				   structure.  */
};

typedef struct poldi_ctx_s *poldi_ctx_t;

#endif
