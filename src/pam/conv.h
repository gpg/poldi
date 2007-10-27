#ifndef CONV_H
#define CONV_H

#include <gpg-error.h>
#include <stdarg.h>

#include "common/poldi-ctx-opaque.h"

gpg_error_t conv_tell (poldi_ctx_t ctx, const char *fmt, ...);
gpg_error_t conv_ask (poldi_ctx_t ctx, int ask_secret, char **response,
		      const char *fmt, ...);

#endif
