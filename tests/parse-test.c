#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#include <gpg-error.h>

#include <simpleparse.h>
#include <simplelog.h>

enum opt_ids
  {
    FOO = 1,
    BAR,
    BAZ
  };

static simpleparse_opt_spec_t opt_specs[] =
  {
    { FOO, "foo", 'f', SIMPLEPARSE_ARG_REQUIRED, 0, "the foo switch requires an argument" },
    { BAR, "bar", 'b', SIMPLEPARSE_ARG_OPTIONAL, 0, "the bar switch takes an optional argument" },
    { BAZ, "baz", 0, SIMPLEPARSE_ARG_NONE, 0, "the baz switch takes no argument" },
    { 0 }
  };

static void
logcb (void *cookie, log_level_t level, const char *fmt, va_list ap)
{
  const char *prefix = cookie;

  fprintf (stderr, "(level %i) [%s] ", level, prefix);
  vfprintf (stderr, fmt, ap);
  fprintf (stderr, "\n");
}

static gpg_error_t
parsecb (void *cookie, simpleparse_opt_spec_t spec, const char *arg)
{
  const char *prefix = cookie;

  printf ("[%s] opt: '%s', argument: '%s'\n", prefix, spec.long_opt, arg);

  return 0;
}

int
main (int argc, const char **argv)
{
  simpleparse_handle_t handle = NULL;
  gpg_error_t err = 0;
  const char **rest_args;

  assert (argc > 0);

  /* Init.  */
  err = simpleparse_create (&handle);
  assert (!err);

  simpleparse_set_parse_cb (handle, parsecb, "parse-test parser");
  simpleparse_set_log_cb (handle, logcb, "parse-test logger");
  simpleparse_set_specs (handle, opt_specs);

  /* Parse command-line arguments. */
  err = simpleparse_parse (handle, 0, argc - 1, argv + 1, &rest_args);
  if (err)
    {
      fprintf (stderr, "simpleparse_parse returned error: %s\n",
	       gpg_strerror (err));
      goto out;
    }

  printf ("Rest args: ");
  while (*rest_args)
    {
      printf ("%s%s", *rest_args, *(rest_args + 1) ? ", " : "");
      rest_args++;
    }
  printf ("\n");

  /* Parse stdin as config file. */
  err = simpleparse_parse_stream (handle, 0, stdin);
  if (err)
    {
      fprintf (stderr, "simpleparse_parse_stream returned error: %s\n",
	       gpg_strerror (err));
      goto out;
    }

 out:

  simpleparse_destroy (handle);

  return !!err;
}
