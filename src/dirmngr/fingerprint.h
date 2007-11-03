#ifndef FINGERPRINT_H
#define FINGERPRINT_H

#include <ksba.h>

unsigned char *gpgsm_get_fingerprint (ksba_cert_t cert, int algo,
                                      unsigned char *array, int *r_len);
char *gpgsm_get_fingerprint_string (ksba_cert_t cert, int algo);
char *gpgsm_get_fingerprint_hexstring (ksba_cert_t cert, int algo);
unsigned long gpgsm_get_short_fingerprint (ksba_cert_t cert);
unsigned char *gpgsm_get_keygrip (ksba_cert_t cert, unsigned char *array);
char *gpgsm_get_keygrip_hexstring (ksba_cert_t cert);
int  gpgsm_get_key_algo_info (ksba_cert_t cert, unsigned int *nbits);
char *gpgsm_get_certid (ksba_cert_t cert);

#endif
