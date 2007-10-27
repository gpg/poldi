#ifndef POLDI_CTX_H
#define POLDI_CTX_H

#include <security/pam_modules.h>

#include "scd/scd.h"

#include "poldi-ctx-opaque.h"


struct poldi_ctx_s
{
  /* Options. */
  const char *logfile;
  unsigned int wait_timeout;

  /* Scdaemon */
  scd_context_t scd;

  pam_handle_t *pam_handle;
  const struct pam_conv *pam_conv;
};

#endif
