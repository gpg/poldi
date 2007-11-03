#ifndef DIRMNGR_H
#define DIRMNGR_H

#include <gpg-error.h>
#include <stdio.h>
#include <ksba.h>

typedef struct dirmngr_ctx_s *dirmngr_ctx_t;

gpg_error_t dirmngr_connect (dirmngr_ctx_t *ctx, unsigned int flags);
void dirmngr_disconnect (dirmngr_ctx_t ctx);
gpg_error_t dirmngr_lookup_url (dirmngr_ctx_t ctx,
				const char *url, ksba_cert_t *cert);
gpg_error_t dirmngr_isvalid (dirmngr_ctx_t ctx, ksba_cert_t cert);

#endif
