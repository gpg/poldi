/* poldi.c - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004 Free Software Foundation, Inc.
 
   This file is part of Libgcrypt.
  
   Libgcrypt is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Libgcrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>

#include <stdio.h>
#include <errno.h>

#include <gpg-error.h>

#include "../jnlib/argparse.h"
#include "../jnlib/xmalloc.h"

#include "options.h"

#include <defs.h>



#define DEFAULT_PCSC_DRIVER "libpcsclite.so"



typedef gpg_err_code_t (*opts_parse_callback_t) (ARGPARSE_ARGS *arg);

/* Option IDs.  */
enum arg_opt_ids
  {
    arg_ctapi_driver = 500,
    arg_pcsc_driver,
    arg_reader_port,
    arg_disable_ccid,
    arg_disable_opensc,
  };

/* Option specifications. */
static ARGPARSE_OPTS arg_opts[] =
  {
    {
      arg_ctapi_driver, "ctapi-driver", 2,
      "|NAME|use NAME as ct-API driver"
    },
    {
      arg_pcsc_driver, "pcsc-driver", 2,
      "|NAME|use NAME as PC/SC driver"
    },
    {
      arg_reader_port, "reader-port", 2,
      "|N|connect to reader at port N"
    },
    {
      arg_disable_ccid, "disable-ccid", 0,
#ifdef HAVE_LIBUSB
      N_("do not use the internal CCID driver")
#else
      "@"
#endif
    },
    {
      arg_disable_opensc, "disable-opensc", 0,
#ifdef HAVE_OPENSC
      N_("do not use the OpenSC layer")
#else
      "@"
#endif
    },
    { 0 }
  };

/* Set defaults.  */
struct opt opt =
  {
    0,
    0,
    0,
    0,
    0,
    NULL,
    NULL,
    DEFAULT_PCSC_DRIVER,
    NULL,
    0,
    0,
    0
  };



/* Process options.  */
static gpg_err_code_t
options_parse_do (FILE *options_fp, const char *options_filename,
		  unsigned int *line_no,
		  ARGPARSE_ARGS *pargs, ARGPARSE_OPTS *opts,
		  opts_parse_callback_t cb)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  while (optfile_parse (options_fp, options_filename, line_no, pargs, opts)
	 && (! err))
    err = (*cb) (pargs);
  
  return err;
}

static gpg_err_code_t
options_callback (ARGPARSE_ARGS *parg)
{
  gpg_err_code_t err = GPG_ERR_NO_ERROR;

  switch (parg->r_opt)
    {
    case arg_ctapi_driver:
      opt.ctapi_driver = xstrdup (parg->r.ret_str);
      break;

    case arg_pcsc_driver:
      opt.pcsc_driver = xstrdup (parg->r.ret_str);
      break;

    case arg_reader_port:
      opt.reader_port = xstrdup (parg->r.ret_str);
      break;

    case arg_disable_ccid:
      opt.disable_ccid = 1;
      break;

    case arg_disable_opensc:
      opt.disable_opensc = 1;
      break;

    default:
      err = GPG_ERR_INTERNAL;	/* FIXME?  */
      break;
    }

  return err;
}

gpg_err_code_t
options_init (void)
{
  const char *options_file = POLDI_CONF_FILE;
  ARGPARSE_ARGS pargs = { NULL, NULL, 0 };
  gpg_err_code_t err = GPG_ERR_NO_ERROR;
  unsigned int line_no = 0;
  FILE *options_fp = NULL;
  char **argv = NULL;
  int argc = 0;

  options_fp = fopen (options_file, "r");
  if (options_fp)
    {
      pargs.argc = &argc;
      pargs.argv = &argv;
      pargs.flags = 1;
      err = options_parse_do (options_fp, options_file,
			      &line_no, &pargs, arg_opts,
			      options_callback);
      fclose (options_fp);
    }

  return err;
}
