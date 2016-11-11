/* scd.h - Interface to Scdaemon
   Copyright (C) 2007, 2008, 2009 g10code GmbH. 

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

#ifndef POLDI_SCD_H
#define POLDI_SCD_H

#include <poldi.h>

#include "util/simplelog.h"

struct scd_context;

typedef struct scd_context *scd_context_t;

struct scd_cardinfo
{
  char *serialno;    /* malloced hex string. */
  char *disp_name;   /* malloced. */
  char *pubkey_url;  /* malloced. */
  char *login_data;  /* malloced. */
  char *disp_lang;   /* malloced. */
  char fpr1valid;
  char fpr2valid;
  char fpr3valid;
  char fpr1[20];
  char fpr2[20];
  char fpr3[20];
};

typedef struct scd_cardinfo scd_cardinfo_t;

#define SCD_FLAG_VERBOSE (1 << 0)

/* Fork it off and work by pipes.  Returns proper error code or zero
   on success.  */
gpg_error_t scd_connect (scd_context_t *scd_ctx, int use_agent,
			 const char *scd_path, const char *scd_options,
			 log_handle_t loghandle);

/* Disconnect from SCDaemon; destroy the context SCD_CTX.  */
void scd_disconnect (scd_context_t scd_ctx);

typedef int (*scd_pincb_t) (void *data, const char *, char *, size_t);

void scd_set_pincb (scd_context_t scd_ctx,
		    scd_pincb_t pincb, void *cookie);

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
gpg_error_t scd_serialno (scd_context_t ctx, char **r_serialno);

/* Read information from card and fill the cardinfo structure
   CARDINFO.  Returns proper error code, zero on success.  */
int scd_learn (scd_context_t ctx,
	       struct scd_cardinfo *cardinfo);

/* Simply release the cardinfo structure INFO.  INFO being NULL is
   okay.  */
void scd_release_cardinfo (struct scd_cardinfo cardinfo);

/* Create a signature using the current card. CTX is the handle for
   the scd subsystem.  KEYID identifies the key on the card to use for
   signing.  INDATA/INDATALEN is the input for the signature function.
   The signature created is written into newly allocated memory in
   *R_BUF, *R_BUFLEN will hold the length of the signature. */
gpg_error_t scd_pksign (scd_context_t ctx,
			const char *keyid,
			const unsigned char *indata, size_t indatalen,
			unsigned char **r_buf, size_t *r_buflen);

/* Read a key with ID and return it in an allocate buffer pointed to
   by r_BUF as a valid S-expression. */
int scd_readkey (scd_context_t ctx,
		 const char *id, gcry_sexp_t *key);

/* Sends a GETINFO command for WHAT to the scdaemon through CTX.  The
   newly allocated result is stored in *RESULT.  Returns proper error
   code, zero on success.  */
int scd_getinfo (scd_context_t ctx, const char *what, char **result);

/* Initializer objet for struct scd_cardinfo instances.  */
extern struct scd_cardinfo scd_cardinfo_null;

#endif
