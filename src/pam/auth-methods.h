/* auth-methods.h - Auth method related definitions for Poldi.
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

#ifndef AUTH_METHODS_H
#define AUTH_METHODS_H

enum
  {
#ifdef ENABLE_AUTH_METHOD_SIMPLEDB
    AUTH_METHOD_SIMPLEDB,
#endif
#ifdef ENABLE_AUTH_METHOD_X509
    AUTH_METHOD_X509,
#endif
#ifdef ENABLE_AUTH_METHOD_TEST
    AUTH_METHOD_TEST,
#endif
    AUTH_METHOD_NONE,
  };

typedef int (*auth_method_func_t) (poldi_ctx_t ctx);

#endif
