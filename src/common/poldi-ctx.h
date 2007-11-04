#ifndef POLDI_CTX_H
#define POLDI_CTX_H

#include <config.h>

#include <security/pam_modules.h>

#include "scd/scd.h"
#ifdef ENABLE_AUTH_METHOD_X509
# include "dirmngr/dirmngr.h"
#endif

#include "poldi-ctx-opaque.h"

struct poldi_ctx_s
{
  /* Options. */
  const char *logfile;
  unsigned int auth_method;
  unsigned int wait_timeout;
  int debug;

  /* Scdaemon. */
  scd_context_t scd;

#ifdef ENABLE_AUTH_METHOD_X509
  /* Dirmngr. */
  dirmngr_ctx_t dirmngr;
#endif

  pam_handle_t *pam_handle;
  const struct pam_conv *pam_conv;
};

#endif
