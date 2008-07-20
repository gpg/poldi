/* simpleparse.h - Minimalistic parser
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

/* This is a minimalistic parser for command-line arguments and
   configuration files. Design goals are:

   - small and flexible,
   - no global variables,
   - uses callbacks. */

#ifndef SIMPLEPARSE_H
#define SIMPLEPARSE_H

#include <poldi.h>

#include <stdio.h>
#include <stdarg.h>

#include <util/simplelog.h>

enum simpleparse_arg
  {
    SIMPLEPARSE_ARG_NONE,
    SIMPLEPARSE_ARG_OPTIONAL,
    SIMPLEPARSE_ARG_REQUIRED
  };

typedef struct
{
  int id;
  const char *long_opt;
  int short_opt;
  enum simpleparse_arg arg;
  unsigned flags;
  const char *description; /* optional option description */
} simpleparse_opt_spec_t;
typedef struct simpleparse_handle *simpleparse_handle_t;

gpg_error_t simpleparse_create (simpleparse_handle_t *handle);
void simpleparse_destroy (simpleparse_handle_t handle);

void simpleparse_set_loghandle (simpleparse_handle_t handle,
				log_handle_t loghandle);

typedef gpg_error_t (*simpleparse_parse_cb_t) (void *cookie, simpleparse_opt_spec_t spec, const char *arg);

void simpleparse_set_parse_cb (simpleparse_handle_t handle,
			       simpleparse_parse_cb_t parse_cb, void *cookie);

gpg_error_t simpleparse_set_specs (simpleparse_handle_t handle, simpleparse_opt_spec_t *specs);

void simpleparse_set_name (simpleparse_handle_t handle, const char *program_name);
void simpleparse_set_package (simpleparse_handle_t handle, const char *package_name);
void simpleparse_set_copyright (simpleparse_handle_t handle, const char *copyright_info);
void simpleparse_set_version (simpleparse_handle_t handle, const char *program_version);
void simpleparse_set_bugaddress (simpleparse_handle_t handle, const char *bugaddress);
void simpleparse_set_author (simpleparse_handle_t handle, const char *author);
void simpleparse_set_license (simpleparse_handle_t handle, const char *license);
void simpleparse_set_description (simpleparse_handle_t handle, const char *program_description);
void simpleparse_set_syntax (simpleparse_handle_t handle, const char *syntax_description);
void simpleparse_set_streams (simpleparse_handle_t handle, FILE *stream_stdout, FILE *stream_stderr);

gpg_error_t simpleparse_parse (simpleparse_handle_t handle, unsigned int flags,
			       unsigned int argc, const char **argv, const char ***rest_args);

gpg_error_t simpleparse_parse_file (simpleparse_handle_t handle, unsigned int flags,
				    const char *filename);

gpg_error_t simpleparse_parse_stream (simpleparse_handle_t handle, unsigned int flags,
				      FILE *stream);

#endif
