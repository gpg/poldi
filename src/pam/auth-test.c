/* auth-test.c - dummy authentication backend for Poldi.
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

#include "poldi-ctx.h"
#include "conv.h"

int
auth_method_test (poldi_ctx_t ctx)
{
  gpg_error_t err;
  char *answer;
  int ret;

  ret = 0;			/* AUTH FAIL.  */

  /* FIXME: quiet?  */
  err = conv_ask (ctx, 0, &answer, "Complete the sequence 'foo': ");
  if (err)
    goto out;

  if (strcmp (answer, "bar") == 0)
    /* Success! */
    ret = 1;

 out:

  return ret;
}
