/* parse-test.c - test program for simpleparse.
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

/* For Poldi I wrote a minimalistic library for parsing configuration
   files and command-line arguments named "simpleparse".  This is a
   test program for simpleparse.  -mo */
 
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#include <gpg-error.h>

#include <simpleparse.h>
#include <simplelog.h>

enum opt_ids
  {
    FOO = 1,
    BAR,
    BAZ
  };

static simpleparse_opt_spec_t opt_specs[] =
  {
    { FOO, "foo", 'f', SIMPLEPARSE_ARG_REQUIRED, 0, "the foo switch requires an argument" },
    { BAR, "bar", 'b', SIMPLEPARSE_ARG_OPTIONAL, 0, "the bar switch takes an optional argument" },
    { BAZ, "baz", 0, SIMPLEPARSE_ARG_NONE, 0, "the baz switch takes no argument" },
    { 0 }
  };

static gpg_error_t
parsecb (void *cookie, simpleparse_opt_spec_t spec, const char *arg)
{
  const char *prefix = cookie;

  printf ("[%s] opt: '%s', argument: '%s'\n", prefix, spec.long_opt, arg);

  return 0;
}

int
main (int argc, const char **argv)
{
  simpleparse_handle_t handle = NULL;
  gpg_error_t err = 0;
  const char **rest_args;
  log_handle_t loghandle = NULL;

  assert (argc > 0);

  /* Init.  */
  err = log_create (&loghandle);
  assert (!err);

  err = log_set_backend_stream (loghandle, stderr);
  assert (!err);

  err = simpleparse_create (&handle);
  assert (!err);

  simpleparse_set_parse_cb (handle, parsecb, "parse-test parser");
  simpleparse_set_loghandle (handle, loghandle);
  simpleparse_set_specs (handle, opt_specs);

  /* Parse command-line arguments. */
  err = simpleparse_parse (handle, 0, argc - 1, argv + 1, &rest_args);
  if (err)
    {
      fprintf (stderr, "simpleparse_parse returned error: %s\n",
	       gpg_strerror (err));
      goto out;
    }

  printf ("Rest args: ");
  if (rest_args)
    {
      while (*rest_args)
	{
	  printf ("%s%s", *rest_args, *(rest_args + 1) ? ", " : "");
	  rest_args++;
	}
    }
  printf ("\n");

  /* Parse stdin as config file. */
  err = simpleparse_parse_stream (handle, 0, stdin);
  if (err)
    {
      fprintf (stderr, "simpleparse_parse_stream returned error: %s\n",
	       gpg_strerror (err));
      goto out;
    }

 out:

  simpleparse_destroy (handle);

  return !!err;
}
