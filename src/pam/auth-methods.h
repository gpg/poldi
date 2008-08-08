/* auth-methods.h - Auth method definitions (Poldi)
   Copyright (C) 2008 g10 Code GmbH
 
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

#ifndef POLDI_AUTH_METHODS_H
#define POLDI_AUTH_METHODS_H

#include <poldi.h>

#include <util/simpleparse.h>

#include "auth-support/ctx.h"



/* This function is called at initialization time (before
   authentication method specific argument parsing is done) in order
   to properly setup an authentication method specific cookie
   object.  */
typedef gpg_error_t (*auth_method_func_init_t) (void **cookie);

/* This function is called after an authentication run in order to
   free any resources allocated through the call to the initialization
   function.  */
typedef void (*auth_method_func_deinit_t) (void *cookie);

/* Try to authenticate a user. The user's identity on the system is
   figured out during the authentication process.  COOKIE is the
   cookie for this authentication method.  CTX is the Poldi context
   object. On successful authentication, the newly allocated username
   as which the user has been authenticated is stored in *USERNAME.
   Returns TRUE on success, FALSE on failure. */
typedef int (*auth_method_func_auth_t) (poldi_ctx_t ctx, void *cookie,
					char **username);

/* Try to authenticate a user as USERNAME.  COOKIE is the cookie for
   this authentication method. CTX is the Poldi context object.
   Returns TRUE on success, FALSE on failure. */
typedef int (*auth_method_func_auth_as_t) (poldi_ctx_t ctx, void *cookie,
					   const char *username);

struct auth_method_parse_cookie
{
  poldi_ctx_t poldi_ctx;
  void *method_ctx;
};

/* Each authentication method must define one such object.  */
struct auth_method_s
{
  auth_method_func_init_t func_init;
  auth_method_func_deinit_t func_deinit;
  auth_method_func_auth_t func_auth;
  auth_method_func_auth_as_t func_auth_as;
  simpleparse_opt_spec_t *opt_specs;
  simpleparse_parse_cb_t parsecb;
  const char *config;
};

typedef struct auth_method_s *auth_method_t;

#endif
