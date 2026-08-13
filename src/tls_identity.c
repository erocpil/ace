#include "tls_identity.h"
#include <string.h>
#include <openssl/x509v3.h>
#include "define.h"

int tls_identity_check_hostname(const char *hostname, X509 *cert)
{
	if (!hostname || !hostname[0])
		return 1;  /* no hostname policy configured */

	if (!cert)
		return 0;

	if (X509_check_host(cert, hostname, strlen(hostname), 0, NULL) != 1) {
		elog("hostname mismatch: expected '%s'", hostname);
		return 0;
	}

	blog("hostname '%s' verified", hostname);
	return 1;
}
