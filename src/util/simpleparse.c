/* simpleparse.c - Minimalistic parser
   Copyright (C) 2008 g10 Code GmbH
 
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

#include <util-local.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <errno.h>

#include <gpg-error.h>

#include "simplelog.h"
#include "simpleparse.h"
#include "support.h"

struct simpleparse_handle
{
  unsigned flags;		   /* General flags. */
  simpleparse_parse_cb_t parse_cb; /* Parser callback. */
  void *parse_cookie;		   /* Cookie for parser callback. */
  simpleparse_i18n_cb_t i18n_cb;   /* Callback for i18n. */
  void *i18n_cookie;		   /* Cookie for i18n callback. */
  log_handle_t loghandle;
  const char *program_name;			   /* Name of the program.  */
  const char *package_name;			   /* Name of the package */
  const char *version;		   /* Version of the program. */
  const char *program_description;	   /* General description of the program. */
  const char *bug_address;		   /* Address for bugreports. */
  const char *syntax_description;	   /* Description of command-line syntax. */
  const char *copyright_info;		   /* Copyright information. */
  simpleparse_opt_spec_t *specs;   /* Specifications for the supported options. */
  FILE *stream_stdout;
  FILE *stream_stderr;
};

/** String list. **/

#define TOKENSIZE 512

/* For now, we use static allocation... */
typedef char token_t[TOKENSIZE];

/* Install the logging handle LOGHANDLE in HANDLE.  */
void
simpleparse_set_loghandle (simpleparse_handle_t handle,
			   log_handle_t loghandle)
{
  assert (handle);
  handle->loghandle = loghandle;
}

gpg_error_t
simpleparse_set_specs (simpleparse_handle_t handle, simpleparse_opt_spec_t *specs)
{
  assert (specs);
  handle->specs = specs;
  /* FIXME, necessary to check for INT_MAX overflow? */
  return 0;
}

/* This function looks up the specification structure for a long
   option by it's name in the context of HANDLE.  The name is given as
   NAME. On success the struct is stored in *SPEC. Returns proper
   error code. The only non-zero error code returned by this function
   is GPG_ERR_UNKNOWN_OPTION in case the option requested could not be
   found. */
static gpg_error_t
lookup_opt_spec_long (simpleparse_handle_t handle,
		      const char *name, simpleparse_opt_spec_t *spec)
{
  gpg_error_t err = 0;
  unsigned int i;

  assert (name);

  for (i = 0; handle->specs[i].long_opt; i++)
    if (!strcmp (name, handle->specs[i].long_opt))
      break;

  if (handle->specs[i].long_opt)
    *spec = handle->specs[i];
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}

/* This function looks up the specification structure for a long
   option by it's short one-letter name in the context of HANDLE.  The
   name is given as NAME. On success the struct is stored in
   *SPEC. Returns proper error code. The only non-zero error code
   returned by this function is GPG_ERR_UNKNOWN_OPTION in case the
   option requested could not be found. */
static gpg_error_t
lookup_opt_spec_short (simpleparse_handle_t handle,
		       const char name, simpleparse_opt_spec_t *spec)
{
  gpg_error_t err = 0;
  unsigned int i;

  assert (name);

  for (i = 0; handle->specs[i].long_opt; i++)
    if (name == handle->specs[i].short_opt)
      break;

  if (handle->specs[i].long_opt)
    *spec = handle->specs[i];
  else
    err = gpg_error (GPG_ERR_UNKNOWN_OPTION);

  return err;
}

static const char *
translate (simpleparse_handle_t handle, const char *msg)
{
  if (handle->i18n_cb)
    return (*handle->i18n_cb) (handle->i18n_cookie, msg);
  else
    return msg;
}
      
static void
display_bugreports (simpleparse_handle_t handle, unsigned int flags)
{
  fprintf (handle->stream_stdout,
	   translate (handle, N_("Please report bugs to <%s>.\n")),
	   handle->bug_address);
}

static void
display_usage (simpleparse_handle_t handle, unsigned int flags)
{
  if (handle->syntax_description)
    fprintf (handle->stream_stdout, "%s\n", handle->syntax_description);
}

static void
display_version (simpleparse_handle_t handle, unsigned int flags)
{
  fprintf (handle->stream_stdout, "%s ", handle->program_name);
  if (handle->package_name)
    fprintf (handle->stream_stdout, "(%s) ", handle->package_name);
  fprintf (handle->stream_stdout, "%s\n", handle->version);

  fprintf (handle->stream_stdout, "%s\n",
	   translate (handle, handle->copyright_info));
}

static void
display_help (simpleparse_handle_t handle, unsigned int flags)
{
  simpleparse_opt_spec_t *specs = handle->specs;
  FILE *out = handle->stream_stdout;
  const char *s;
  int i, j, indent;

  assert (handle->stream_stdout);

  display_version (handle, flags);
  display_usage (handle, flags);

  putc ('\n', handle->stream_stdout);

  /* Get max. length of long options */
  for(i = indent = 0; specs[i].short_opt; i++)
    {
      if (specs[i].long_opt)
	if ((j = strlen (specs[i].long_opt)) > indent && j < 35)
	  indent = j;
    }

  /* example: " -v, --verbose   Viele Sachen ausgeben" */
  indent += 10;

  for (i = 0; specs[i].id; i++)
    {
      if (specs[i].description)
	s = translate (handle, specs[i].description);
      else
	s = NULL;

      j = 3;
      if (specs[i].short_opt)
	fprintf (out, " -%c", specs[i].short_opt);
      else
	fputs ("   ", out);

      if (specs[i].long_opt)
	{
	  j += fprintf (out,
			"%c --%s", specs[i].short_opt ? ',' : ' ',
			specs[i].long_opt);
	  fputs ("   ", out);
	  j += 3;
	}
      for(; j < indent; j++)
	putc (' ', out);

      if (s)
	{
	  if (*s && j > indent)
	    {
	      putc ('\n', out);
	      for(j = 0; j < indent; j++)
		putc (' ', out);
	    }
	  for(; *s; s++)
	    putc (*s, out);
	}

      putc ('\n', out);
    }
  putc ('\n', out);

  display_bugreports (handle, flags);
}


static gpg_error_t
internal_parse_args (simpleparse_handle_t handle, unsigned int flags,
		     unsigned int argc, const char **argv, const char ***rest_args)
{
  simpleparse_opt_spec_t spec;
  gpg_error_t err;
  const char **arg;

  assert (argv);
  assert (rest_args);

  arg = argv;
  err = 0;

  while (1)
    {
      if (!argc)
	/* No more args. */
	break;

      if (!strcmp (*arg, "--"))
	{
	  /* This marks the end of the switches. */
	  arg++;
	  argc--;
	  break;
	}

      /* Special switches.  */
      if (!strcmp (*arg, "--help"))
	{
	  display_help (handle, flags);
	  arg++;
	  argc--;
	  break;
	}

      /* Special switches.  */
      if (!strcmp (*arg, "--version"))
	{
	  display_version (handle, flags);
	  arg++;
	  argc--;
	  break;
	}

      if (!strcmp (*arg, "-"))
	/* We consider this arg to be a non-switch. */
	break;

      if ((*arg)[0] != '-')
	/* First non-switch argument. */
	break;

      /* Next arg is either long or short option. */
      if ((*arg)[1] == '-')
	/* Long option.  */
	err = lookup_opt_spec_long (handle, (*arg) + 2, &spec);
      else
	/* Short option. */
	err = lookup_opt_spec_short (handle, *((*arg) + 1), &spec);

      if (err)
	{
	  /* Invalid option. */
	  log_msg_error (handle->loghandle,
			 translate (handle, N_("unknown option '%s'")), *arg);
	  break;
	}

      if (spec.arg == SIMPLEPARSE_ARG_OPTIONAL)
	{
	  if (argc >= 2 && (*(arg+1)) && (*(arg+1))[0] != '-')
	    {
	      err = (*handle->parse_cb) (handle->parse_cookie, spec, *(arg + 1));
	      if (err)
		{
		  log_msg_error (handle->loghandle,
				 translate (handle,
					    N_("parse-callback returned error '%s' for argument '%s'")),
				 gpg_strerror (err), spec.long_opt);
		  goto out;
		}
	      arg += 2;
	      argc -= 2;
	    }
	  else
	    {
	      err = (*handle->parse_cb) (handle->parse_cookie, spec, NULL);
	      if (err)
		{
		  log_msg_error (handle->loghandle,
				 translate (handle,
					    N_("parse-callback returned error '%s' for argument '%s'")),
				 gpg_strerror (err), spec.long_opt);
		  goto out;
		}
	      arg++;
	      argc--;
	    }
	}
      else if (spec.arg == SIMPLEPARSE_ARG_REQUIRED)
	{
	  if (argc >= 2 && (*(arg+1)) && (*(arg+1))[0] != '-')
	    {
	      err = (*handle->parse_cb) (handle->parse_cookie, spec, *(arg + 1));
	      if (err)
		{
		  log_msg_error (handle->loghandle,
				 translate (handle,
					    N_("parse-callback returned error '%s' for argument '%s'")),
				 gpg_strerror (err), spec.long_opt);
		  goto out;
		}
	      arg += 2;
	      argc -= 2;
	    }
	  else
	    {
	      /* Argument missing. */
	      err = gpg_error (GPG_ERR_MISSING_VALUE);
	      log_msg_error (handle->loghandle,
			     translate (handle,
					N_("missing required argument for '%s'")),
			     spec.long_opt);
	      goto out;
	    }
	}
      else if (spec.arg == SIMPLEPARSE_ARG_NONE)
	{
	  /* No arg allowed.  */
	  err = (*handle->parse_cb) (handle->parse_cookie, spec, NULL);
	  if (err)
	    {
	      log_msg_error (handle->loghandle,
			     translate (handle,
					N_("parse-callback returned error '%s' for argument '%s'")),
			     gpg_strerror (err), spec.long_opt);
	      goto out;
	    }
	  arg++;
	  argc--;
	}
    }

 out:

  if (err || (argc == 0))
    *rest_args = NULL;
  else
    *rest_args = arg;

  return err;
}
	    
typedef struct
{
  token_t *tokens;
  unsigned int size;
} token_list_t;

static gpg_error_t
token_list_init (token_list_t *list)
{
  list->tokens = NULL;
  list->size = 0;

  return 0;
}

static gpg_error_t
token_list_add (token_list_t *list, const char *item, int length)
{
  gpg_error_t err = 0;
  int item_length;
  token_t *tokens = NULL;

  if (!item)
    goto out;

  if (list->size == UINT_MAX)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto out;
    }

  if (length == -1)
    {
      item_length = my_strlen (item);
      if (item_length)
	{
	  err = gpg_error (GPG_ERR_TOO_LARGE);
	  goto out;
	}
    }
  else
    item_length = length;

  if (item_length >= TOKENSIZE)
    {
      err = gpg_error (GPG_ERR_TOO_LARGE);
      goto out;
    }

  tokens = xtryrealloc (list->tokens, sizeof (*list->tokens) * (list->size + 1));
  if (!tokens)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  list->tokens = tokens;
  assert (item_length < TOKENSIZE);
  memcpy (list->tokens[list->size], item, item_length);
  list->tokens[list->size][item_length] = 0;
  list->size++;

 out:

  return err;
}

static gpg_error_t
token_list_clear (token_list_t *list)
{
  if (list->tokens)
    xfree (list->tokens);
  list->tokens = NULL;
  list->size = 0;
  return 0;
}

static gpg_error_t
internal_parse_line (char *line, token_list_t *tokens)
{
  token_list_t token_list;
  gpg_error_t err;
  char *p;

  err = token_list_init (&token_list);
  if (err)
    goto out;

  /* Start. */
  p = line;

  /* Special case for comments and empty lines.  */
  while (isspace (*p))
    p++;
  if ((*p == '#') || (*p == '\n') || (*p == '\0'))
    goto out;

  /* This loops over the tokens contained in the line. */
  while (1)
    {
      int quoting_char = 0;
      unsigned int i = 0;

      /* Skip whitespaces before tokens. */
      while ((*p == ' ') || (*p == '\t'))
	p++;

      if (*p == '\0')
	/* This was an empty line. */
	break;

      /* There seems to be another token. */

      if ((*p == '"') || (*p == '\''))
	{
	  /* The token is quoted; remember quoting character. */
	  quoting_char = *p;
	  p++;
	}

      /* The new token starts at P and is at least one byte long.  If
	 quoting_char is positive, the current token is quoted. */
      i = 1;

      while (1)
	{
	  if (!p[i])
	    {
	      if (quoting_char)
		{
		  /* Quoting not properly terminated.  */
		  err = gpg_error (GPG_ERR_SYNTAX);
		  goto out;
		}
	      else
		break;
	    }
	  else if ((p[i] == ' ') || (p[i] == '\t'))
	    {
	      /* Whitespace! */
	      if (!quoting_char)
		/* Not inside of a quoted token, therefore this is a
		   token delimiter. */
		break;
	    }
	      
	  else if (p[i] == '\\')
	    {
	      abort ();
	      /* We do not allow escape characters yet. */
	    }
	  else if (p[i] == quoting_char)
	    {
	      /* Terminating quote characters, ends current token. */
	      i++;
	      break;
	    }

	  /* Move forward in current token. */
	  i++;
	}

      /* Now we have a new token in {p[0], p[1], ..., p[i-1]}; i is
	 positive. In case of quoted tokens, we must subtract one
	 byte, since the trailing quote character is not part of the
	 token. */

      err = token_list_add (&token_list, p, i - !!quoting_char);
      if (err)
	goto out;

      p += i;
    }
	      
 out:

  if (err)
    {
      token_list_clear (&token_list);
    }
  else
    *tokens = token_list;

  return err;
}

static gpg_error_t
internal_process_tokens (simpleparse_handle_t handle, token_list_t tokens)
{
  simpleparse_opt_spec_t spec;
  gpg_error_t err;

  err = 0;

  assert (1 <= tokens.size);

  err = lookup_opt_spec_long (handle, tokens.tokens[0], &spec);
  if (err)
    {
      log_msg_error (handle->loghandle,
		     translate (handle, N_("unknown option '%s'")), tokens.tokens[0]);
      goto out;
    }

  switch (spec.arg)
    {
    case SIMPLEPARSE_ARG_NONE:
      if (tokens.size > 1)
	{
	  log_msg_error (handle->loghandle,
			 translate (handle,
				    N_("too many arguments specified for option '%s'")),
			 tokens.tokens[0]);
	  err = gpg_error (GPG_ERR_SYNTAX);
	  goto out;
	}
      break;
    case SIMPLEPARSE_ARG_REQUIRED:
      if (tokens.size < 2)
	{
	  log_msg_error (handle->loghandle,
			 translate (handle,
				    N_("missing required argument for '%s'")),
			 tokens.tokens[0]);
	  err = gpg_error (GPG_ERR_SYNTAX);
	  goto out;
	}
      else if (tokens.size > 2)
	{
	  log_msg_error (handle->loghandle,
			 translate (handle,
				    N_("too many arguments specified for option '%s'")),
			 tokens.tokens[0]);
	  err = gpg_error (GPG_ERR_SYNTAX);
	  goto out;
	}
      break;

    case SIMPLEPARSE_ARG_OPTIONAL:
      break;
    }

  err = (*handle->parse_cb) (handle->parse_cookie, spec,
			     (tokens.size == 2) ? tokens.tokens[1] : NULL);

 out:

  return err;
}

/* Replaces the first occurence of a newline character in the string S
   with a NUL character. */
static void
cut_trailing_newline (char *s)
{
  char *nl = strchr (s, '\n');
  if (nl)
    *nl = '\0';
}

/* Parse the stream STREAM using the state contained in HANDLE. FLAGS
   is not used yet. Returns proper error code.  */
static gpg_error_t
internal_parse_stream (simpleparse_handle_t handle, unsigned int flags, FILE *stream)
{
  size_t line_size;
  char *line;
  int length;
  token_list_t tokens;
  gpg_error_t err;
  int ret;

  tokens.tokens = NULL;
  tokens.size = 0;
  err = 0;

  while (1)
    {
      line = NULL;
      line_size = 0;

      ret = getline (&line, &line_size, stream);
      if (ret == -1)
	{
	  if (!feof (stream))
	    err = gpg_error_from_errno (errno);
	  goto out;
	}

      /* We simply ignore NUL characters in line.  */
      length = my_strlen (line);
      if (length == -1)
	{
	  err = GPG_ERR_TOO_LARGE;
	  goto out;
	}

      /* Ignore terminating newline character.  */
      cut_trailing_newline (line);
      
      /* Split line into tokens. */

      err = internal_parse_line (line, &tokens);
      if (err)
	goto out;

      /* Process. */
      if (tokens.size > 0)
	{
	  err = internal_process_tokens (handle, tokens);
	  if (err)
	    goto out;
	}

      /* Release. */

      token_list_clear (&tokens);
      free (line);
      line = NULL;
    }

 out:

  if (line)
    free (line);		/* Allocated by getline, thus standard
				   free. */
  return err;
}

/* Parse the stream STREAM using the state contained in HANDLE. FLAGS
   is not used yet. Returns proper error code.  */
gpg_error_t
simpleparse_parse_stream (simpleparse_handle_t handle, unsigned int flags,
			  FILE *stream)
{
  return internal_parse_stream (handle, flags, stream);
}

/* Parse the file FILENAME using the state contained in HANDLE. FLAGS
   is not used yet. Returns proper error code.  */
gpg_error_t
simpleparse_parse_file (simpleparse_handle_t handle, unsigned int flags,
			const char *filename)
{
  gpg_error_t err;
  FILE *fp;

  fp = fopen (filename, "r");
  if (!fp)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  err = internal_parse_stream (handle, flags, fp);

 out:

  if (fp)
    fclose (fp);

  return err;
}

/* Parse the argument vector ARGC/ARGV using the state contained in
   HANDLE. On successful parsing, a pointer to the rest arguments is
   stored in *REST_ARGS. FLAGS is not used. Returns proper error
   code. */
gpg_error_t
simpleparse_parse (simpleparse_handle_t handle, unsigned int flags,
		   unsigned int argc, const char **argv, const char ***rest_args)
{
  gpg_error_t err;
  const char **rest;

  err = internal_parse_args (handle, flags, argc, argv, &rest);
  if (err)
    goto out;

  if (rest && (! rest_args))
    {
      /* Caller does not expect rest arguments, but there are some. */
      err = gpg_error (GPG_ERR_UNEXPECTED);
      goto out;
    }

  if (rest_args)
    *rest_args = rest;

 out:

  return err;
}

static struct simpleparse_handle simpleparse_handle_init;

/* Create a new, plain handle and store it in *HANDLE. Returns proper
   error code.  */
gpg_error_t
simpleparse_create (simpleparse_handle_t *handle)
{
  gpg_error_t err = 0;

  *handle = xtrymalloc (sizeof (**handle));
  if (!*handle)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  **handle = simpleparse_handle_init;

 out:

  return err;
}

static void
internal_release_handle (simpleparse_handle_t handle)
{
  assert (handle);
  xfree (handle);
}

/* Destroy the handle HANDLE. */
void
simpleparse_destroy (simpleparse_handle_t handle)
{
  if (handle)
    internal_release_handle (handle);
}

/* Install the parser callback and it's cookie in HANDLE.  */
void
simpleparse_set_parse_cb (simpleparse_handle_t handle,
			  simpleparse_parse_cb_t parse_cb, void *cookie)
{
  assert (handle);

  handle->parse_cb = parse_cb;
  handle->parse_cookie = cookie;
}

void
simpleparse_set_i18n_cb (simpleparse_handle_t handle,
			 simpleparse_i18n_cb_t i18n_cb, void *cookie)
{
  assert (handle);

  handle->i18n_cb = i18n_cb;
  handle->i18n_cookie = cookie;
}

void
simpleparse_set_name (simpleparse_handle_t handle, const char *program_name)
{
  handle->program_name = program_name;
}

void
simpleparse_set_package (simpleparse_handle_t handle, const char *package_name)
{
  handle->package_name = package_name;
}

void
simpleparse_set_copyright (simpleparse_handle_t handle, const char *copyright_info)
{
  handle->copyright_info = copyright_info;
}

void
simpleparse_set_version (simpleparse_handle_t handle, const char *program_version)
{
  handle->version = program_version;
}

void
simpleparse_set_bugaddress (simpleparse_handle_t handle, const char *bug_address)
{
  handle->bug_address = bug_address;
}

void
simpleparse_set_author (simpleparse_handle_t handle, const char *author)
{
  /* FIXME */
}

void
simpleparse_set_license (simpleparse_handle_t handle, const char *license)
{
  /* FIXME */
}

void
simpleparse_set_description (simpleparse_handle_t handle, const char *program_description)
{
  handle->program_description = program_description;
}

void
simpleparse_set_syntax (simpleparse_handle_t handle, const char *syntax_description)
{
  handle->syntax_description = syntax_description;
}

void
simpleparse_set_streams (simpleparse_handle_t handle, FILE *stream_stdout, FILE *stream_stderr)
{
  handle->stream_stdout = stream_stdout;
  handle->stream_stderr = stream_stderr;
}

/* END*/
