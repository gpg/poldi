/* simplelog.c - Simple logging subsystem for Poldi
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
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <syslog.h>

#include <gpg-error.h>

#include "simplelog.h"

struct log_handle
{
  log_backend_t backend;
  log_level_t min_level;
  unsigned int flags;
  char prefix[LOG_PREFIX_LENGTH];
  FILE *stream;
};

static gpg_error_t
internal_release_backend (log_handle_t handle)
{
  assert (handle->backend != LOG_BACKEND_NONE);

  switch (handle->backend)
    {
    case LOG_BACKEND_NONE:
    case LOG_BACKEND_STREAM:
    case LOG_BACKEND_SYSLOG:
      /* Nothing to do here. */
      break;

    case LOG_BACKEND_FILE:
      /* FIXME: error checking.  */
      assert (handle->stream);
      fclose (handle->stream);
      break;
    }

  handle->backend = LOG_BACKEND_NONE;

  return 0;
}

static gpg_error_t
internal_set_backend_file (log_handle_t handle, const char *filename)
{
  gpg_error_t err = 0;
  FILE *stream = NULL;

  assert (handle->backend == LOG_BACKEND_NONE);

  stream = fopen (filename, "a");
  if (!stream)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  handle->backend = LOG_BACKEND_FILE;
  handle->stream = stream;

 out:

  return err;
}

static gpg_error_t
internal_set_backend_stream (log_handle_t handle, FILE *stream)
{
  assert (handle->backend == LOG_BACKEND_NONE);
  assert (stream);

  handle->backend = LOG_BACKEND_STREAM;
  handle->stream = stream;

  return 0;
}

static gpg_error_t
internal_set_backend_syslog (log_handle_t handle)
{
  assert (handle->backend == LOG_BACKEND_NONE);

  handle->backend = LOG_BACKEND_SYSLOG;

  return 0;
}

gpg_error_t
log_create (log_handle_t *handle)
{
  gpg_error_t err = 0;

  *handle = xtrymalloc (sizeof (**handle));
  if (!*handle)
    {
      err = gpg_error_from_errno (errno);
      goto out;
    }

  (*handle)->backend = LOG_BACKEND_NONE;
  (*handle)->min_level = LOG_LEVEL_INFO;
  (*handle)->flags = 0;
  (*handle)->prefix[0] = 0;

 out:

  return err;
}

void
log_destroy (log_handle_t handle)
{
  if (handle)
    {
      if (handle->backend != LOG_BACKEND_NONE)
	internal_release_backend (handle);
      xfree (handle);
    }
}

void
log_set_flags (log_handle_t handle, unsigned int flags)
{
  handle->flags |= flags;
}

void
log_unset_flags (log_handle_t handle, unsigned int flags)
{
  handle->flags &= ~flags;
}

gpg_error_t
log_set_backend_file (log_handle_t handle, const char *filename)
{
  gpg_error_t err;

  assert (handle);

  if (handle->backend != LOG_BACKEND_NONE)
    internal_release_backend (handle);

  err = internal_set_backend_file (handle, filename);

  return err;
}

gpg_error_t
log_set_backend_stream (log_handle_t handle, FILE *stream)
{
  gpg_error_t err;

  assert (handle);

  if (handle->backend != LOG_BACKEND_NONE)
    internal_release_backend (handle);

  err = internal_set_backend_stream (handle, stream);

  return err;
}

gpg_error_t
log_set_backend_syslog (log_handle_t handle)
{
  gpg_error_t err;

  assert (handle);

  if (handle->backend != LOG_BACKEND_NONE)
    internal_release_backend (handle);

  err = internal_set_backend_syslog (handle);

  return err;
}


void
log_set_prefix (log_handle_t handle, const char *prefix)
{
  assert (handle);

  strncpy (handle->prefix, prefix, sizeof (handle->prefix) - 1);
  handle->prefix[sizeof (handle->prefix) - 1] = 0;
}

void
log_set_min_level (log_handle_t handle, log_level_t min_level)
{
  assert (handle);

  if (min_level == LOG_LEVEL_DEBUG
      || min_level == LOG_LEVEL_INFO
      || min_level == LOG_LEVEL_ERROR
      || min_level == LOG_LEVEL_FATAL)
    handle->min_level = min_level;
}

static gpg_error_t
internal_log_write (log_handle_t handle, log_level_t level,
		    const char *fmt, va_list ap)
{
  gpg_error_t err;

  assert (handle->backend != LOG_BACKEND_NONE);

  /* FIXME: shall we do error checking here?  And what if an error
     occurs?  */

  if (level < handle->min_level)
    /* User does not want to receive messages for level smaller than
       min_level. */
    return 0;

  if (handle->backend == LOG_BACKEND_SYSLOG)
    {
      int syslog_priority;

      switch (level)
	{
	case LOG_LEVEL_DEBUG:
	  syslog_priority = LOG_DEBUG;
	  break;

	case LOG_LEVEL_INFO:
	  syslog_priority = LOG_INFO;
	  break;

	case LOG_LEVEL_ERROR:
	  syslog_priority = LOG_ERR;
	  break;

	case LOG_LEVEL_FATAL:
	  syslog_priority = LOG_ALERT;
	  break;

	default:
	  /* FIXME: what to do when the user passes an invalid log
	     level? -mo */
	  syslog_priority = LOG_ERR;
	  break;
	}
	  
      vsyslog (LOG_MAKEPRI (LOG_AUTH, syslog_priority), fmt, ap);
      err = 0;
    }
  else if (handle->backend == LOG_BACKEND_STREAM
	   || handle->backend == LOG_BACKEND_FILE)
    {
      FILE *stream = handle->stream;

      assert (stream);

      if ((handle->flags & LOG_FLAG_WITH_PREFIX) && (*handle->prefix != 0))
	fprintf (stream, "%s ", handle->prefix);

      if (handle->flags & LOG_FLAG_WITH_TIME)
	{
	  struct tm *tp;
	  time_t atime = time (NULL);
          
	  tp = localtime (&atime);
	  fprintf (stream, "%04d-%02d-%02d %02d:%02d:%02d ",
		   1900+tp->tm_year, tp->tm_mon+1, tp->tm_mday,
		   tp->tm_hour, tp->tm_min, tp->tm_sec);
	}

      if (handle->flags & LOG_FLAG_WITH_PID)
	fprintf (stream, "[%u] ", (unsigned int) getpid ());

      switch (level)
	{
	case LOG_LEVEL_ERROR:
	case LOG_LEVEL_FATAL:
	  fprintf (stream, "error: ");
	  break;

	case LOG_LEVEL_DEBUG:
	  fprintf (stream, "debug: ");
	  break;

	case LOG_LEVEL_INFO:
	  break;
	}

      vfprintf (stream, fmt, ap);
      putc ('\n', stream);

      err = 0;
    }

  return err;
}

gpg_error_t
log_write (log_handle_t handle, log_level_t level,
	   const char *fmt, ...)
{
  gpg_error_t err = 0;

  assert (handle);

  if (handle->backend != LOG_BACKEND_NONE)
    {
      va_list ap;

      va_start (ap, fmt);
      err = internal_log_write (handle, level, fmt, ap);
      va_end (ap);
    }

  return err;
}

gpg_error_t
log_write_va (log_handle_t handle, log_level_t level,
	      const char *fmt, va_list ap)
{
  gpg_error_t err = 0;

  assert (handle);

  if (handle->backend != LOG_BACKEND_NONE)
    err = internal_log_write (handle, level, fmt, ap);

  return err;
}

gpg_error_t
log_msg_debug (log_handle_t handle, const char *fmt, ...)
{
  gpg_error_t err;
  va_list ap;

  if (!handle)
    return 0;

  va_start (ap, fmt);
  err = log_write_va (handle, LOG_LEVEL_DEBUG, fmt, ap);
  va_end (ap);

  return err;
}

gpg_error_t
log_msg_info  (log_handle_t handle, const char *fmt, ...)
{
  gpg_error_t err;
  va_list ap;

  if (!handle)
    return 0;

  va_start (ap, fmt);
  err = log_write_va (handle, LOG_LEVEL_INFO, fmt, ap);
  va_end (ap);

  return err;
}

gpg_error_t
log_msg_error (log_handle_t handle, const char *fmt, ...)
{
  gpg_error_t err;
  va_list ap;

  if (!handle)
    return 0;

  va_start (ap, fmt);
  err = log_write_va (handle, LOG_LEVEL_ERROR, fmt, ap);
  va_end (ap);

  return err;
}

gpg_error_t
log_msg_fatal (log_handle_t handle, const char *fmt, ...)
{
  gpg_error_t err;
  va_list ap;

  if (!handle)
    return 0;

  va_start (ap, fmt);
  err = log_write_va (handle, LOG_LEVEL_FATAL, fmt, ap);
  va_end (ap);

  return err;
}

/* END */
