#ifndef __TLS_IDENTITY_H__
#define __TLS_IDENTITY_H__

#include <openssl/x509.h>

/* Verify the leaf certificate's hostname against the expected name
 * (RFC 6125 / X509_check_host).
 *
 * Returns 1 on match (or when no hostname policy is configured), 0 on
 * mismatch.  A NULL or empty hostname means "no hostname policy", so the
 * certificate is accepted on that axis. */
int tls_identity_check_hostname(const char *hostname, X509 *cert);

#endif
