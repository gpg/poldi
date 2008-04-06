/* getpin-cb.h - PAM conversation abstraction for Poldi.
   Copyright (C) 2007, 2008 g10 Code GmbH
 
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

#ifndef GETPIN_CB_H
#define GETPIN_CB_H

/* This is the Assuan callback, which is to be used for SCDaemon
   transactions.  It takes care of PIN querying through PAM
   conversation functions.  This function is used by authentiation
   methods (in src/pam/auth-XXX/).  OPAQUE is expected to be a conv_t
   object. */

int getpin_cb (void *opaque, const char *info, char *buf, size_t maxbuf);

#endif
