/* card.c - High-Level access to OpenPGP smartcards.
   Copyright (C) 2004 g10 Code GmbH.
 
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <gcrypt.h>

#include <gpg-error.h>

#include <apdu.h>
#include <iso7816.h>
#include <tlv.h>

gpg_error_t
card_open (const char *port, int *slot,
	   unsigned char **serial_no, size_t *serial_no_n)
{
  char const aid[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char *serial = NULL;
  size_t serial_n = 0;
  int slot_new = -1;

  slot_new = apdu_open_reader (port);
  if (slot_new != -1)
    {
      /* Select OpenPGP Application.  */
      err = iso7816_select_application (slot_new, aid, sizeof (aid));
      if (! err)
	/* Get serial number.  */
	err = iso7816_get_data (slot_new, 0x004F, &serial, &serial_n);
      /* FIXME: verify correctness of CHV status bytes?  */
    }
  else
    err = GPG_ERR_INTERNAL;	/* ? */

  if (! err)
    {
      *slot = slot_new;
      *serial_no = serial;
      *serial_no_n = serial_n;
    }
  else
    {
      if (slot_new != -1)
	apdu_close_reader (slot_new);
    }

  return err;
}

void
card_close (int slot)
{
  apdu_close_reader (slot);
}

gpg_error_t
card_info (int slot, unsigned char *key_fpr, unsigned char **login, size_t *login_n)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char *fprs = NULL;
  const unsigned char *value = NULL;
  size_t fprs_n = 0, value_n = 0;
  unsigned int i = 0, j = 0;
  unsigned char *login_new = NULL;
  size_t login_new_n = 0;

  /* Read fingerprint.  */
  err = iso7816_get_data (slot, 0x6E, &fprs, &fprs_n);
  if (! err)
    {
      value = find_tlv (fprs, fprs_n, 0x00C5, &value_n);
      if (! (value
	     && (! (value_n > (fprs_n - (value - fprs))))
	     && (value_n >= 60))) /* FIXME: Shouldn't this be "==
				     60"?  */
	err = GPG_ERR_INTERNAL;	/* ? */
      else
	/* Copy out third key FPR.  */
	for (i = 0, j = 0; i < 20; i++, j += 2)
	  sprintf (key_fpr + j, "%02X", (value + (2 * 20))[i]);
    }

  if (! err)
    {
      /* Read login data (account).  */
      err = iso7816_get_data (slot, 0x005E, &login_new, &login_new_n);
      if (! err)
	{
	  *login = login_new;
	  *login_n = login_new_n;
	}
    }

  return err;
}

gpg_error_t
card_pin_provide (int slot, unsigned char *pin)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;

  err = iso7816_verify (slot, 0x82, pin, strlen (pin));

  return err;
}


gpg_error_t
card_sign (int slot, unsigned char *data, size_t data_n,
	   unsigned char **data_signed, size_t *data_signed_n)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  unsigned char *digestinfo = NULL;
  size_t digestinfo_n = 0;
  unsigned char md_asn[100] = {};
  size_t md_asn_n = sizeof (md_asn);

  err = gcry_md_get_asnoid (GCRY_MD_SHA1, md_asn, &md_asn_n);
  if (! err)
    {
      digestinfo_n = md_asn_n + data_n;
      digestinfo = malloc (digestinfo_n);
      if (! digestinfo)
	err = GPG_ERR_ENOMEM;
    }

  if (! err)
    {
      memcpy (digestinfo, md_asn, md_asn_n);
      memcpy (digestinfo + md_asn_n, data, data_n);
      
      err = iso7816_internal_authenticate (slot, digestinfo, digestinfo_n,
					   data_signed, data_signed_n);
    }

  if (digestinfo)
    free (digestinfo);

  return err;
}
