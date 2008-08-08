/* getpin-cb.h - getpin Assuan Callback (Poldi)
   Copyright (C) 2007, 2008 g10 Code GmbH
 
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

/* This is an assuan callback. It's called when an assuan server
   (scdaemon) wants to retrieve the PIN from Poldi. This specific
   implementation of the getpin callback API tries to retrieve the PIN
   through PAM conversation. */

#ifndef GETPIN_CB_H
#define GETPIN_CB_H

#include "ctx.h"

/* Structure for passing data to getpin_cb. */
struct getpin_cb_data
{
  poldi_ctx_t poldi_ctx;	/* Poldi context; contains the PAM
				   conversation object, etc. */
};

/* This is the Assuan callback, which is to be used for SCDaemon
   transactions.  It takes care of PIN querying through PAM
   conversation functions.  This function is used by authentiation
   methods.  OPAQUE is expected to be a pointer to struct
   getpin_cb_data. */
int getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf);

#endif
