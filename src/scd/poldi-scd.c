/* call-scd.c - Interface to Scdaemon
 *	Copyright (C) 2001, 2002, 2005 Free Software Foundation, Inc.
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

#include "scd.h"

#include "common/poldi-ctx.h"

/* Try to connect to the agent via socket or fork it off and work by
   pipes.  Returns proper error code or zero on success.  */
int
poldi_scd_connect (poldi_ctx_t ctx,
		   const char *agent_infostr,
		   const char *scd_path,
		   unsigned int flags)
{
  return scd_connect (&ctx->scd, agent_infostr, scd_path, flags);
}

/* Disconnect from SCDaemon; destroy the context SCD_CTX.  */
int
poldi_scd_disconnect (poldi_ctx_t ctx)
{
  return scd_disconnect (ctx->scd);
}

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
int
poldi_scd_serialno (poldi_ctx_t ctx,
		    char **r_serialno)
{
  return scd_serialno (ctx->scd, r_serialno);
}

/* Read information from card and fill the cardinfo structure
   CARDINFO.  Returns proper error code, zero on success.  */
int
poldi_scd_learn (poldi_ctx_t ctx,
		 struct scd_cardinfo *cardinfo)
{
  return scd_learn (ctx->scd, cardinfo);
}

/* Simply release the cardinfo structure INFO.  INFO being NULL is
   okay.  */
void
poldi_scd_release_cardinfo (struct scd_cardinfo *cardinfo)
{
  return scd_release_cardinfo (cardinfo);
}

/* Create a signature using the current card */
int
poldi_scd_pksign (poldi_ctx_t ctx,
		  const char *keyid,
		  int (*getpin_cb)(void *, const char *, char*, size_t),
		  void *getpin_cb_arg,
		  const unsigned char *indata, size_t indatalen,
		  unsigned char **r_buf, size_t *r_buflen)
{
  return scd_pksign (ctx->scd, keyid, getpin_cb, getpin_cb_arg,
		     indata, indatalen, r_buf, r_buflen);
}

/* Read a key with ID and return it in an allocate buffer pointed to
   by r_BUF as a valid S-expression. */
int
poldi_scd_readkey (poldi_ctx_t ctx,
		   const char *id, gcry_sexp_t *key)
{
  return scd_readkey (ctx->scd, id, key);
}

/* Sends a GETINFO command for WHAT to the scdaemon through CTX.  The
   newly allocated result is stored in *RESULT.  Returns proper error
   code, zero on success.  */
int
poldi_scd_getinfo (poldi_ctx_t ctx,
		   const char *what,
		   char **result)
{
  return scd_getinfo (ctx->scd, what, result);
}

/* Reset the SCD if it has been used.  */
int
poldi_scd_reset (poldi_ctx_t ctx)
{
  return scd_reset (ctx->scd);
}

