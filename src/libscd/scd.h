/* scd.h
   Copyright (C) 2004 Free Software Foundation, Inc.
 
   This file is part of Poldi.
  
   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU Lesser general Public License as
   published by the Free Software Foundation; either version 2.1 of
   the License, or (at your option) any later version.
  
   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.
  
   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef SCD_H
#define SCD_H

#ifdef GPG_ERR_SOURCE_DEFAULT
#error GPG_ERR_SOURCE_DEFAULT already defined
#endif
#define GPG_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_USER_1
#include <gpg-error.h>

#include "../jnlib/xmalloc.h"
#define xfree(a)         free ((a))
#define xtrymalloc(a)    malloc ((a))
#define xtrycalloc(a,b)  calloc ((a),(b))
#define xtryrealloc(a,b) realloc ((a),(b))
#define xtrystrdup(a)    strdup ((a))

#include "../jnlib/logging.h"

#include "../options.h"

#define DBG_COMMAND_VALUE 1	/* debug commands i/o */
#define DBG_MPI_VALUE	  2	/* debug mpi details */
#define DBG_CRYPTO_VALUE  4	/* debug low level crypto */
#define DBG_MEMORY_VALUE  32	/* debug memory allocation stuff */
#define DBG_CACHE_VALUE   64	/* debug the caching */
#define DBG_MEMSTAT_VALUE 128	/* show memory statistics */
#define DBG_HASHING_VALUE 512	/* debug hashing operations */
#define DBG_ASSUAN_VALUE 1024   
#define DBG_CARD_IO_VALUE 2048

#define DBG_COMMAND 0
#define DBG_CRYPTO  0
#define DBG_MEMORY  0
#define DBG_CACHE   0
#define DBG_HASHING 0
#define DBG_ASSUAN  0
#define DBG_CARD_IO 0

#endif /* SCD_H */
