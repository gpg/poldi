/* options.h - Poldi option handling
   Copyright (C) 2004 Free Software Foundation, Inc.
 
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

/* Global flags.  */
struct opt
{
  unsigned int debug; /* debug flags (DBG_foo_VALUE) */
  int debug_sc;     /* OpenSC debug level */
  int verbose;      /* verbosity level */
  int dry_run;      /* don't change any persistent data */
  int batch;        /* batch mode */
  const char *homedir; /* configuration directory name */
  const char *ctapi_driver; /* Library to access the ctAPI. */
  const char *pcsc_driver;  /* Library to access the PC/SC system. */
  const char *reader_port;  /* NULL or reder port to use. */
  int disable_opensc;  /* Disable the use of the OpenSC framework. */
  int disable_ccid;    /* Disable the use of the internal CCID driver. */
  int allow_admin;     /* Allow the use of admin commands for certain
                          cards. */
};

extern struct opt opt;

gpg_err_code_t options_init (void);

#endif
