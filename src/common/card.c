/* card.c - High-Level access to OpenPGP smartcards.
   Copyright (C) 2004, 2005 g10 Code GmbH.
 
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>

#include <gcrypt.h>

#include <libscd/apdu.h>
#include <libscd/iso7816.h>
#include <libscd/tlv.h>

#define opt opt_scd

#include "options.h"
#include <../jnlib/xmalloc.h>

#include <syslog.h>

/* To help tracking changed cards we use this counter and save the
   last known status.  */
static unsigned int change_counter;
static unsigned int last_status;

/* This functions opens the card terminal specified by PORT.  On
   success an according handle, the slot ID, will be stored in *SLOT.
   Returns proper error code.  */
gpg_error_t
card_open (const char *port, int *slot)
{
  gpg_error_t err;
  int slot_new;

  /* Open reader.  */
  slot_new = apdu_open_reader (port);
  if (slot_new == -1)
    {
      err = gpg_error (GPG_ERR_CARD);
      goto out;
    }

  err = 0;
  *slot = slot_new;

 out:

  return err;
}

/* Wait until a new card has been inserted into the reader. If TIMEOUT
   is non-zero, do not wait longer than TIMEOUT seconds.

   Returns 0 in case a card has been inserted; returns 1 in case the
   timeout has been reached without a card being inserted.  */
static int
wait_for_card (int slot, int require_card_switch, unsigned int timeout)
{
  unsigned int changed;
  unsigned int status;
  time_t t0;
  time_t t;

  if (timeout)
    time (&t0);
  //  else
  /* FIXME: silence compiler?  */
    

  while (1)
    {
      status = changed = 0;
      apdu_get_status (slot, 0, &status, &changed);
      if (((! require_card_switch) || (changed != change_counter))
	  || ((status & 2) != (last_status & 2)))
        {
          change_counter = changed;
          last_status = status;
          if ((status & 2))
            return 0;
        } 
#ifdef HAVE_NANOSLEEP      
      {
        struct timespec t;

        t.tv_sec = 0;
        t.tv_nsec = 300000000;
        nanosleep (&t, NULL);  /* Wait 300ms.  */
      }
#else
      sleep (1);
#endif

      if (timeout)
	{
	  time (&t);
	  if ((t - t0) > timeout)
	    return 1;
	}
    }
}

/* This functions initializes a card, which is to be inserted in the
   slot SLOT; initializing it means selecting the OpenPGP application.

   Depending on the boolean value WAIT, do not fail in case there is
   no card in SLOT but wait until a card becomes available; do not
   wait more then TIMEOUT seconds or wait forever in case TIMEOUT is
   zero.

   Depending on the boolean value REQUIRE_CARD_SWITCH, require that a
   card, which is already inserted at the time of this function call,
   needs to be reinserted.

   Returns proper error code.  */
gpg_error_t
card_init (int slot, int wait, unsigned int timeout, int require_card_switch)
{
  /* This is the AID (Application IDentifier) for OpenPGP.  */
  char const aid[] = { 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01 };
  gpg_error_t err;

  /* A specified timeout makes no sense in case waiting is not
     desired.  */
  assert (! ((! wait) && timeout));

  apdu_get_status (slot, 0, &last_status, &change_counter);
  if (wait)
    {
      int ret;

      apdu_activate (slot);
      ret = wait_for_card (slot, require_card_switch, timeout);
      if (ret)
	{
	  err = gpg_error (GPG_ERR_CARD_NOT_PRESENT);
	  goto out;
	}
      else
	err = 0;
    }
  else
    err = 0;

  /* Select OpenPGP Application.  */
  err = iso7816_select_application (slot, aid, sizeof (aid));

 out:

  return err;
}

/* This function releases the slot handle specified by SLOT.  */
void
card_close (int slot)
{
  apdu_close_reader (slot);
}

/* This function retrieves basic information from the card, which is
   to be accessed through SLOT and which needs to be initialized.

   If SERIAL_NO is not NULL, retrieve the card's serial number and
   store it in a newly allocated C string, which is to be stored in
   *SERIAL_NO.

   If CARD_VERSION is not NULL, store the card's version number in
   *CARD_VERSION.

   If FINGERPRINT is not NULL, retrieve the signing key's fingerprint
   and store it in newly allocated C string, which is to be stored in
   *FINGERPRINT.

   Returns proper error code.  */
gpg_error_t
card_info (int slot, char **serial_no,
	   unsigned int *card_version, char **fingerprint)
{
  size_t fingerprint_new_n;
  char *fingerprint_new;
  char *serial_no_new;
  const unsigned char *value;
  unsigned int version;
  unsigned char *data;
  size_t value_n;
  size_t data_n;
  gpg_error_t err;
  unsigned int i;

  fingerprint_new = NULL;
  serial_no_new = NULL;
  version = 0;
  err = 0;

  if (serial_no || card_version)
    {
      /* Retrieve serial number and/or card_version.  */

      err = iso7816_get_data (slot, 0x004F, &data, &data_n);
      if (err)
	goto out;

      /* FIXME: assert correct?  */
      assert (data_n == 16);

      if (serial_no)
	{
	  serial_no_new = malloc ((data_n * 2) + 1);
	  if (serial_no_new)
	    for (i = 0; i < data_n; i++)
	      sprintf (serial_no_new + (i * 2), "%02X", data[i]);
	  else
	    err = gpg_error_from_errno (errno);
	}
      else
	serial_no_new = NULL;

      if (card_version)
	{
	  version = data[6] << 8;
	  version |= data[7];
	}

      free (data);
      if (err)
	goto out;
    }

  if (fingerprint)
    {
      fingerprint_new = NULL;

      err = iso7816_get_data (slot, 0x6E, &data, &data_n);
      if (err)
	goto out;

      value = find_tlv (data, data_n, 0x00C5, &value_n);
      if (! (value
	     && (! (value_n > (data_n - (value - data))))
	     && (value_n >= 60))) /* FIXME: Shouldn't this be "==
				     60"?  */
	err = gpg_error (GPG_ERR_INTERNAL);

      if (! err)
	{
	  fingerprint_new_n = 41;
	  fingerprint_new = malloc (fingerprint_new_n);
	  if (! fingerprint_new)
	    err = gpg_error_from_errno (errno);
	}

      if (! err)
	/* Copy out third key FPR.  */
	for (i = 0; i < 20; i++)
	  sprintf (fingerprint_new + (i * 2), "%02X", (value + (2 * 20))[i]);

      free (data);
      if (err)
	goto out;
    }
  else
    fingerprint_new = NULL;

  if (serial_no)
    *serial_no = serial_no_new;
  if (card_version)
    *card_version = version;
  if (fingerprint)
    *fingerprint = fingerprint_new;

 out:

  if (err)
    {
      free (serial_no_new);
      free (fingerprint_new);
    }

  return err;
}

/* This function retrieves the signing key of an initialized card
   accessed through SLOT and stores it, converted into an
   S-Expression, in *KEY.  Returns proper error code.  */
gpg_error_t
card_read_key (int slot, gcry_sexp_t *key)
{
  const unsigned char *data;
  const unsigned char *e;
  const unsigned char *n;
  unsigned char *buffer;
  size_t buffer_n;
  size_t data_n;
  size_t e_n;
  size_t n_n;
  gcry_mpi_t e_mpi;
  gcry_mpi_t n_mpi;
  int rc;
  gpg_error_t err;
  gcry_sexp_t key_sexp;

  buffer = NULL;
  data = NULL;
  e = NULL;
  n = NULL;
  e_mpi = NULL;
  n_mpi = NULL;
  key_sexp = NULL;

  rc = iso7816_read_public_key (slot, "\xA4", 2, &buffer, &buffer_n);
  if (rc)
    {
      err = gpg_error (GPG_ERR_CARD);
      goto out;
    }

  /* Extract key data.  */
  data = find_tlv (buffer, buffer_n, 0x7F49, &data_n);
  if (! data)
    {
      err = gpg_error (GPG_ERR_CARD);
      goto out;
    }

  /* Extract n.  */
  n = find_tlv (data, data_n, 0x0081, &n_n);
  if (! n)
    {
      err = gpg_error (GPG_ERR_CARD);
      goto out;
    }
  
  /* Extract e.  */
  e = find_tlv (data, data_n, 0x0082, &e_n);
  if (! e)
    {
      err = gpg_error (GPG_ERR_CARD);
      goto out;
    }

  err = gcry_mpi_scan (&n_mpi, GCRYMPI_FMT_USG, n, n_n, NULL);
  if (err)
    goto out;

  err = gcry_mpi_scan (&e_mpi, GCRYMPI_FMT_USG, e, e_n, NULL);
  if (err)
    goto out;

  err = gcry_sexp_build (&key_sexp, NULL,
			 "(public-key (rsa (n %m) (e %m)))", n_mpi, e_mpi);
  if (err)
    goto out;

  *key = key_sexp;

 out:

  free (buffer);
  gcry_mpi_release (e_mpi);
  gcry_mpi_release (n_mpi);

  return err;
}

/* This function sends the PIN contained in PIN to the card accessed
   through SLOT.  WHICH specifies the type of PIN:

   WHICH=1: CHV1
   WHICH=2: CHV2
   WHICH=3: CHV3.

   Returns proper error code.  */
/* FIXME: why unsigned char *pin?  */
gpg_error_t
card_pin_provide (int slot, int which, const unsigned char *pin)
{
  gpg_error_t err = GPG_ERR_NO_ERROR;
  int chv_id;

  if (which == 1)
    chv_id = 0x81;
  else if (which == 2)
    chv_id = 0x82;
  else if (which == 3)
    chv_id = 0x83;
  else
    {
      err = gpg_error (GPG_ERR_INV_ARG);
      goto out;
    }

  err = iso7816_verify (slot, chv_id, pin, strlen (pin));

 out:

  return err;
}

/* This function requests the card accessed through SLOT to sign the
   data in DATA of DATA_N bytes; the signature is to be stored in
   *DATA_SIGNED, it's length in bytes in *DATA_SIGNED_N.  Returns
   proper error code.  */
gpg_error_t
card_sign (int slot, const unsigned char *data, size_t data_n,
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

/* END */
