#ifndef DIRMNGR_H
#define DIRMNGR_H

#include <gpg-error.h>
#include <ksba.h>

#include "common/poldi-ctx-opaque.h"

gpg_error_t poldi_dirmngr_connect (poldi_ctx_t ctx);

gpg_error_t poldi_dirmngr_lookup_url (poldi_ctx_t ctx,
				      const char *url,
				      ksba_cert_t *cert);

gpg_error_t poldi_dirmngr_isvalid (poldi_ctx_t ctx,
				   ksba_cert_t cert);

gpg_error_t poldi_dirmngr_disconnect (poldi_ctx_t ctx);

#endif
