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

#ifndef SIMPLELOG_H
#define SIMPLELOG_H

#include <stdarg.h>
#include <stdio.h>

#include <gpg-error.h>

typedef struct log_handle *log_handle_t;

#define LOG_FLAG_WITH_PREFIX (1 <<  0)
#define LOG_FLAG_WITH_TIME   (1 <<  1)
#define LOG_FLAG_WITH_PID    (1 <<  2)

typedef enum
  {
    LOG_BACKEND_NONE,
    LOG_BACKEND_STREAM,
    LOG_BACKEND_FILE,
    LOG_BACKEND_SYSLOG
  } log_backend_t;
  
typedef enum
  {
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_INFO,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
  } log_level_t;

#define LOG_PREFIX_LENGTH 128

gpg_error_t log_create (log_handle_t *handle);
void log_destroy (log_handle_t handle);

void log_set_flags (log_handle_t handle, unsigned int flags);
void log_unset_flags (log_handle_t handle, unsigned int flags);
void log_set_prefix (log_handle_t handle, const char *prefix);
void log_set_min_level (log_handle_t handle, log_level_t min_level);

gpg_error_t log_set_backend_stream (log_handle_t handle, FILE *fp);
gpg_error_t log_set_backend_file (log_handle_t handle, const char *filename);
gpg_error_t log_set_backend_syslog (log_handle_t handle);

gpg_error_t log_write (log_handle_t handle, log_level_t level,
		       const char *fmt, ...);
gpg_error_t log_write_va (log_handle_t handle, log_level_t level,
			  const char *fmt, va_list ap);

gpg_error_t log_msg_debug (log_handle_t handle, const char *fmt, ...);
gpg_error_t log_msg_info  (log_handle_t handle, const char *fmt, ...);
gpg_error_t log_msg_error (log_handle_t handle, const char *fmt, ...);
gpg_error_t log_msg_fatal (log_handle_t handle, const char *fmt, ...);

#endif
