/* pam-util.c - PAM util functions for Poldi.
 * Copyright (C) 2007 g10 Code GmbH
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <gpg-error.h>
#include <security/pam_modules.h>

#include "poldi-ctx.h"



/* Retrieve the username through the PAM handle contained in CTX and
   store it in *USERNAME.  Returns proper error code.  */
gpg_error_t
retrieve_username_from_pam (poldi_ctx_t ctx, const char **username)
{
  const void *username_void;
  gpg_error_t err;
  int ret;

  ret = pam_get_item (ctx->pam_handle, PAM_USER, &username_void);
  if (ret == PAM_SUCCESS)
    {
      err = 0;
      *username = username_void;
    }
  else
    err = gpg_error (GPG_ERR_INTERNAL);

  return err;
}

/* Make USERNAME available to the application through the PAM handle
   contained in CTX.  Returns proper error code.  */
gpg_error_t
send_username_to_pam (poldi_ctx_t ctx, const char *username)
{
  gpg_error_t err;
  int ret;

  ret = pam_set_item (ctx->pam_handle, PAM_USER, username);
  if (ret == PAM_SUCCESS)
    err = 0;
  else
    err = gpg_error (GPG_ERR_INTERNAL);

  return err;
}
