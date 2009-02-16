/* pam-test.c - simple PAM authentication test program
   Copyright (C) 2007, 2009 g10 Code GmbH
 
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
 
#include <stdio.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>



#define PROGRAM_NAME    "pam-test"
#define PROGRAM_VERSION "0.2"

/* Use the standard conversation function from libpam-misc. */
static struct pam_conv conv =
  {
    misc_conv,
    NULL
  };

static void
print_help (void)
{
  printf ("\
Usage: %s [options] <PAM service name>\n\
Test PAM authentication.\n\
\n\
Options:\n\
 -h, --help      print help information\n\
 -v, --version   print version information\n\
 -u, --username  specify username for authentication\n\
\n\
Report bugs to <moritz@gnu.org>.\n", PROGRAM_NAME);
}

static void
print_version (void)
{
  printf (PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

static void
test_auth (const char *servicename, const char *username)
{
  const void *user_opaque;
  const char *user;
  pam_handle_t *handle;
  int rc;

  /* Connect to PAM.  */
  rc = pam_start (servicename, username, &conv, &handle);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "error: %s\n", pam_strerror (handle, rc));
      goto out;
    }

  /* Try authentication.  */
  rc = pam_authenticate (handle, 0);
  if (rc != PAM_SUCCESS)
    {
      printf ("Authentication failed\n");
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

  return;
}

/* This is a simple test program for PAM authentication.  */
int
main (int argc, char **argv)
{
  const char *servicename;
  const char *username;
  int c;

  servicename = username = NULL;

  while (1)
    {
      static struct option long_options[] =
	{
	  { "version", no_argument, 0, 'v' },
	  { "help", no_argument, 0, 'h' },
	  { "user", required_argument, 0, 'u' },
	  { 0, 0, 0, 0 }
	};
      int option_index = 0;

      c = getopt_long (argc, argv, "vhu:",
		       long_options, &option_index);

      /* Detect the end of the options. */
      if (c == -1)
	break;

      switch (c)
	{
	case 'u':
	  username = strdup (optarg);
	  if (!username)
	    {
	      fprintf (stderr, "failed to duplicate username: %s", strerror (errno));
	      exit (1);
	    }
	  break;

	case 'h':
	  print_help ();
	  exit (0);
	  break;

	case 'v':
	  print_version ();
	  exit (0);
	  break;

	case '?':
	  /* `getopt_long' already printed an error message. */
	  break;

	default:
	  abort ();
	}
    }

  if (argc - optind != 1)
    {
      print_help ();
      exit (1);
    }

  servicename = argv[optind];
  test_auth (servicename, username);

  return 0;
}

/* end */
