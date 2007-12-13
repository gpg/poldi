/* pam-test.c - simple PAM authentication test program
   Copyright (C) 2007 g10 Code GmbH
 
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

#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>



/* Return the value of the environment variable NAME if that is set.
   Return DEFAULT_VAL in case it is unset.  */
static const char *
get_value (const char *name, const char *default_val)
{
  char *env;

  env = getenv (name);
  if (env)
    return env;
  else
    return default_val;
}

/* Use the standard conversation function from libpam-misc. */
static struct pam_conv conv =
  {
    misc_conv,
    NULL
  };

/* This is a simple test program for PAM authentication.  */
int
main (int argc, char **argv)
{
  pam_handle_t *handle;
  int rc;
  const char *service;
  const char *user;
  const void *user_opaque;

  /* Lookup service name and user name.  */
  service = get_value ("PAM_TEST_SERVICE", "");
  user = get_value ("PAM_TEST_USER", NULL);

  /* Connect to PAM.  */
  rc = pam_start (service, user, &conv, &handle);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "error: %s\n", pam_strerror (handle, rc));
      goto out;
    }

  /* Try authentication.  */
  rc = pam_authenticate (handle, 0);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "error: %s\n", pam_strerror (handle, rc));
      goto out;
    }

  printf ("Authentication succeeded\n");

  /* Retrieve name of authenticated identity.  */
  rc = pam_get_item (handle, PAM_USER, &user_opaque);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "error: %s\n", pam_strerror (handle, rc));
      goto out;
    }
  user = user_opaque;
  printf ("Authenticated as user `%s'\n", user);

  /* Disconnect from PAM.  */
  rc = pam_end (handle, rc);
  if (rc != PAM_SUCCESS)
    fprintf (stderr, "error: failed to release PAM handle\n");

 out:

  return !!rc;
}

/* end */
