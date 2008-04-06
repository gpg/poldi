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

#ifndef PAM_UTIL_H
#define PAM_UTIL_H

#include <gpg-error.h>

//#include "ctx.h"

#define PAM_SM_AUTH
#include <security/pam_modules.h>

/* Retrieve the username through the PAM handle contained in CTX and
   store it in *USERNAME.  Returns proper error code.  */
gpg_error_t retrieve_username_from_pam (pam_handle_t *handle, const char **username);

/* Make USERNAME available to the application through the PAM handle
   contained in CTX.  Returns proper error code.  */
gpg_error_t send_username_to_pam (pam_handle_t *handle, const char *username);

#endif
