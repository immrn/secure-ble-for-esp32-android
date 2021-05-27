#ifndef _FILE_APP_SSL_CTX_H_
#define _FILE_APP_SSL_CTX_H_

#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"



// The transport layer has been closed upon a read.
#define SSL_CTX_TRANSPORT_CLOSED 1



typedef struct __ssl_ctx__ {
	// A source of entropy (= random stuff)
	mbedtls_entropy_context entropy;

	// The random number generator
	mbedtls_ctr_drbg_context rng;

	// The keypair that constitutes our identity
	mbedtls_pk_context srv_keys;

	// The CA-signed server certificate to prove our identity to clients
	mbedtls_x509_crt srv_crt;

	// The CA certificate used to validate clients
	mbedtls_x509_crt ca_crt;

	// The configuration spec for the SSL context
	mbedtls_ssl_config config;

	// The actual SSL context
	mbedtls_ssl_context ssl;
} ssl_ctx;

/*	@brief Create a new SSL context with the given parameters.
 *
 *	@param endpoint_role		use MBEDTLS_SSL_IS_SERVER or MBEDTLS_SSL_IS_CLIENT
 */
void ssl_ctx_create(
	ssl_ctx* ctx,
	int endpoint_role,
	const char* srv_key_file,
	const char* srv_crt_file,
	const char* ca_crt_file,
	const char* expected_cn,
	mbedtls_ssl_send_t* send_data_func,
	mbedtls_ssl_recv_timeout_t* recv_data_func,
	void* send_recv_ctx
);

// Destroy an existing SSL context.
void ssl_ctx_destroy(ssl_ctx* ctx);

// Stringify the given mbedtls error code.
const char* ssl_ctx_error_msg(int error_code);

// Perform a handshake with the given SSL context.
// On success, 0 is returned.
// Otherwise, the result is an mbedtls error.
// In that case, the context stays disconnected
// and you can try again to shake hands.
int ssl_ctx_perform_handshake(ssl_ctx* ctx);

// Send the given application data (after a successful handshake).
// On success, 0 is returned.
// Otherwise, the result is an mbedtls error.
// In that case, the context has been disconnected
// and you can try again to shake hands.
int ssl_ctx_send(ssl_ctx* ctx, const unsigned char* data, size_t len);

// Receive the given amount of application data (after a successful handshake).
// On success, 0 is returned.
// If the transport layer has been closed, SSL_CTX_TRANSPORT_CLOSED is returned.
// Otherwise, the result is an mbedtls error.
// In that case, the context has been disconnected
// and you can try again to shake hands.
int ssl_ctx_recv(ssl_ctx* ctx, unsigned char* data, size_t len);

// Close the connection.
void ssl_ctx_close_connection(ssl_ctx* ctx);



#endif /* _FILE_APP_SSL_CTX_H_ */