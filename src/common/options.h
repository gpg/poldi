/* options.h - Poldi option handling
   Copyright (C) 2004 g10 Code GmbH.
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU general Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef OPTIONS_H
#define OPTIONS_H

#include <gpg-error.h>

#include <jnlib/argparse.h>

typedef gpg_error_t (*options_callback_t) (ARGPARSE_ARGS *parg, void *opaque);

gpg_error_t options_parse_argv (options_callback_t callback, void *opaque,
				ARGPARSE_OPTS *arg_opts, int argc, char **argv);

gpg_error_t options_parse_conf (options_callback_t callback, void *opaque,
				ARGPARSE_OPTS *arg_opts, const char *filename);

#endif
