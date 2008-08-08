/* assuan-io-pth.c - Pth version of assua-io.c.
 * Copyright (C) 2002, 2004, 2006, 2007, 2008 Free Software Foundation, Inc.
 *
 * This file is part of Assuan.
 *
 * Assuan is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Assuan is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_W32_SYSTEM
# include <windows.h>
#else
# include <sys/wait.h>
#endif
#include <pth.h>

#include "assuan-defs.h"



#ifndef HAVE_W32_SYSTEM
pid_t 
_assuan_waitpid (pid_t pid, int *status, int options)
{
  return pth_waitpid (pid, status, options);
}
#endif


ssize_t
_assuan_simple_read (assuan_context_t ctx, void *buffer, size_t size)
{
  /* Fixme: For W32 we should better not cast the HANDLE type to int.
     However, this requires changes in w32pth too.  */
  ssize_t retval;
  
  if (_assuan_io_hooks.read_hook
      && _assuan_io_hooks.read_hook (ctx, ctx->inbound.fd, 
                                     buffer, size, &retval) == 1)
    return retval;

  return _assuan_io_read (ctx->inbound.fd, buffer, size);
}

ssize_t
_assuan_simple_write (assuan_context_t ctx, const void *buffer, size_t size)
{
  ssize_t retval;
  
  if (_assuan_io_hooks.write_hook
      && _assuan_io_hooks.write_hook (ctx, ctx->outbound.fd, 
                                      buffer, size, &retval) == 1)
    return retval;
  return _assuan_io_write (ctx->outbound.fd, buffer, size);
}

ssize_t
_assuan_io_read (assuan_fd_t fd, void *buffer, size_t size)
{
  ssize_t retval;
  
  if (_assuan_io_hooks.read_hook
      && _assuan_io_hooks.read_hook (NULL, fd, buffer, size, &retval) == 1)
    return retval;
  return pth_read ((int)fd, buffer, size);
}

ssize_t
_assuan_io_write (assuan_fd_t fd, const void *buffer, size_t size)
{
  ssize_t retval;
  
  if (_assuan_io_hooks.write_hook
      && _assuan_io_hooks.write_hook (NULL, fd, buffer, size, &retval) == 1)
    return retval;
  return pth_write ((int)fd, buffer, size);
}


#ifdef HAVE_W32_SYSTEM
int
_assuan_simple_sendmsg (assuan_context_t ctx, void *msg)
#else
ssize_t
_assuan_simple_sendmsg (assuan_context_t ctx, struct msghdr *msg)
#endif
{
#if defined(HAVE_W32_SYSTEM)
  return _assuan_error (ASSUAN_Not_Implemented);
#else
  /* Pth does not provide a sendmsg function.  Thus we implement it here.  */
  int ret;
  int fd = ctx->outbound.fd;
  int fdmode;

  fdmode = pth_fdmode (fd, PTH_FDMODE_POLL);
  if (fdmode == PTH_FDMODE_ERROR)
    {
      errno = EBADF;
      return -1;
    }
  if (fdmode == PTH_FDMODE_BLOCK)
    {
      fd_set fds;

      FD_ZERO (&fds);
      FD_SET (fd, &fds);
      while ( (ret = pth_select (fd+1, NULL, &fds, NULL, NULL)) < 0
              && errno == EINTR)
        ;
      if (ret < 0)
        return -1;
    }

  while ((ret = sendmsg (fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#endif
}

#ifdef HAVE_W32_SYSTEM
int
_assuan_simple_recvmsg (assuan_context_t ctx, void *msg)
#else
ssize_t
_assuan_simple_recvmsg (assuan_context_t ctx, struct msghdr *msg)
#endif
{
#if defined(HAVE_W32_SYSTEM)
  return _assuan_error (ASSUAN_Not_Implemented);
#else
  /* Pth does not provide a recvmsg function.  Thus we implement it here.  */
  int ret;
  int fd = ctx->inbound.fd;
  int fdmode;

  fdmode = pth_fdmode (fd, PTH_FDMODE_POLL);
  if (fdmode == PTH_FDMODE_ERROR)
    {
      errno = EBADF;
      return -1;
    }
  if (fdmode == PTH_FDMODE_BLOCK)
    {
      fd_set fds;

      FD_ZERO (&fds);
      FD_SET (fd, &fds);
      while ( (ret = pth_select (fd+1, &fds, NULL, NULL, NULL)) < 0
              && errno == EINTR)
        ;
      if (ret < 0)
        return -1;
    }

  while ((ret = recvmsg (fd, msg, 0)) == -1 && errno == EINTR)
    ;
  return ret;
#endif
}


void
_assuan_usleep (unsigned int usec)
{
  pth_usleep (usec);
}
