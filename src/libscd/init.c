/* init.c - Initialize libscd
   Copyright (C) 2004 g10 Code GmbH
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#include <config.h>
#include <scd.h>
#include <ccid-driver.h>

#define DEFAULT_PCSC_DRIVER "libpcsclite.so"

struct scd_opt scd_opt;

void
scd_init (unsigned int debug, int debug_sc, int verbose,
	  const char *ctapi_driver, const char *reader_port,
	  const char *pcsc_driver, int disable_opensc,
	  int disable_ccid, int debug_ccid_driver)
{
  scd_opt.debug = debug;
  scd_opt.debug_sc = debug_sc;
  scd_opt.ctapi_driver = ctapi_driver;
  scd_opt.reader_port = reader_port;
  scd_opt.pcsc_driver = pcsc_driver ? pcsc_driver : DEFAULT_PCSC_DRIVER;
  scd_opt.disable_opensc = disable_opensc;
  scd_opt.disable_ccid = disable_ccid;

  if (debug_ccid_driver)
    ccid_set_debug_level (debug_ccid_driver);
}
