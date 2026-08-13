#define _GNU_SOURCE
#include <assert.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "tls_identity.h"

static X509 *make_cert(const char *cn)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	X509_NAME *name = NULL;

	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	assert(pctx != NULL);
	assert(EVP_PKEY_keygen_init(pctx) == 1);
	assert(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) == 1);
	assert(EVP_PKEY_keygen(pctx, &pkey) == 1);
	EVP_PKEY_CTX_free(pctx);

	cert = X509_new();
	assert(cert != NULL);
	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
	X509_gmtime_adj(X509_get_notBefore(cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert), 3600);
	assert(X509_set_pubkey(cert, pkey) == 1);

	/* No SAN: X509_check_host falls back to the subject CN. */
	name = X509_get_subject_name(cert);
	assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			(const unsigned char *)cn, -1, -1, 0) == 1);
	assert(X509_set_issuer_name(cert, name) == 1);

	assert(X509_sign(cert, pkey, EVP_sha256()) > 0);
	EVP_PKEY_free(pkey);
	return cert;
}

int main(void)
{
	X509 *cert = make_cert("localhost");

	assert(tls_identity_check_hostname("localhost", cert) == 1);
	assert(tls_identity_check_hostname("wronghost.example.com", cert) == 0);
	assert(tls_identity_check_hostname(NULL, cert) == 1);
	assert(tls_identity_check_hostname("", cert) == 1);
	assert(tls_identity_check_hostname("localhost", NULL) == 0);

	X509_free(cert);
	return 0;
}
