/* call-scd.c - Interface to Scdaemon
 *	Copyright (C) 2007 g10code GmbH. 
 *
 * This file is part of Poldi.
 *
 * Poldi is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Poldi is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef POLDI_CALL_SCD_H
#define POLDI_CALL_SCD_H

#include <assuan.h>
#include <gcrypt.h>

struct scd_context;

typedef struct scd_context *scd_context_t;

struct scd_cardinfo
{
  char *serialno;    /* malloced hex string. */
  char *disp_name;   /* malloced. */
  char *login_data;
  char fpr1valid;
  char fpr2valid;
  char fpr3valid;
  char fpr1[20];
  char fpr2[20];
  char fpr3[20];
};

typedef struct scd_cardinfo scd_cardinfo_t;

#define SCD_FLAG_VERBOSE (1 << 0)

int scd_connect (scd_context_t *scd_ctx,
		 const char *scd_infostr,
		 const char *scd_path,
		 unsigned int flags);

int scd_disconnect (scd_context_t scd_ctx);

int scd_serialno (scd_context_t ctx,
		  char **r_serialno);


int scd_learn (scd_context_t ctx,
	       struct scd_cardinfo *cardinfo);

void scd_release_cardinfo (struct scd_cardinfo *cardinfo);

int scd_pksign (scd_context_t ctx,
		const char *keyid,
		int (*getpin_cb)(void *, const char *, char*, size_t),
		void *getpin_cb_arg,
		const unsigned char *indata, size_t indatalen,
		unsigned char **r_buf, size_t *r_buflen);

int scd_readkey (scd_context_t ctx,
		 const char *id, gcry_sexp_t *key);

int scd_getinfo (scd_context_t ctx, const char *what, char **result);

#endif
