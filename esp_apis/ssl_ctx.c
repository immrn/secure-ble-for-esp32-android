#include "ssl_ctx.h"

#include <stdlib.h>
#include <string.h>

// This blob is used as the initial entropy source for the RNG.
#define RNG_PERSONALITY "fb_steigtum"

#ifdef SSL_CTX_DEBUG
static void debug_callback(void* opaque_ctx, int level, const char* file_name, int line_number, const char* msg)
{
    printf("mbedtls_debug: length of upcoming message = %zu", sizeof(msg));
	printf("[mbedtls_debug L%d] (\"%s\" in line %d): %s", level, file_name, line_number, msg);
}
#endif

static void fail_on_error(int err, const char* tag)
{
	if (err != 0)
	{
		printf("[mbedtls_error] (%s) %s", tag, ssl_ctx_error_msg(err));
		exit(-1);
	}
}

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
) {
	// Initialize the entropy source.
	mbedtls_entropy_init(&ctx->entropy);

	// Initialize the RNG and seed it.
	mbedtls_ctr_drbg_init(&ctx->rng);

	int err = mbedtls_ctr_drbg_seed(&ctx->rng, mbedtls_entropy_func, &ctx->entropy, (const unsigned char*)RNG_PERSONALITY, strlen(RNG_PERSONALITY));
	fail_on_error(err, "mbedtls_ctr_drbg_seed");

	// Specify the SSL configuration.
	mbedtls_ssl_config_init(&ctx->config);

	err = mbedtls_ssl_config_defaults(
		&ctx->config,
		endpoint_role,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT
	);

	fail_on_error(err, "mbedtls_ssl_config_defaults");

	// Specify the RNG for the configuration to use.
	mbedtls_ssl_conf_rng(&ctx->config, mbedtls_ctr_drbg_random, &ctx->rng);

	// Load our key pair.
	mbedtls_pk_init(&ctx->srv_keys);

	err = mbedtls_pk_parse_keyfile(&ctx->srv_keys, srv_key_file, "");
	fail_on_error(err, "mbedtls_pk_parse_keyfile");

	// Load the server certificate.
	mbedtls_x509_crt_init(&ctx->srv_crt);

	err = mbedtls_x509_crt_parse_file(&ctx->srv_crt, srv_crt_file);
	fail_on_error(err, "mbedtls_x509_crt_parse_file");

	// Define the server certificate as our own certificate to advertise.
	err = mbedtls_ssl_conf_own_cert(&ctx->config, &ctx->srv_crt, &ctx->srv_keys);
	fail_on_error(err, "mbedtls_ssl_conf_own_cert");

	// Load the CA certificate.
	mbedtls_x509_crt_init(&ctx->ca_crt);

	err = mbedtls_x509_crt_parse_file(&ctx->ca_crt, ca_crt_file);
	fail_on_error(err, "mbedtls_x509_crt_parse_file");

	// Define the CA certificate as the root of our validation chain.
	mbedtls_ssl_conf_ca_chain(&ctx->config, &ctx->ca_crt, NULL);

	// Ensure that client certificates are verified.
	mbedtls_ssl_conf_authmode(&ctx->config, MBEDTLS_SSL_VERIFY_REQUIRED);

	// Specify the debug function if debugging is enabled.
#ifdef SSL_CTX_DEBUG
	mbedtls_ssl_conf_dbg(&ctx->config, debug_callback, NULL);
	mbedtls_debug_set_threshold(4);
#endif

	// Initialize an SSL context with our configuration.
	mbedtls_ssl_init(&ctx->ssl);

	err = mbedtls_ssl_setup(&ctx->ssl, &ctx->config);
	fail_on_error(err, "mbedtls_ssl_setup");

	// Okay, I am not completely sure about this part.
	// According to the documentation, `mbedtls_ssl_set_hostname()` has two jobs:
	//
	// - Setting the SNI extension in ClientHello to select one of multiple hosts
	// - Validating the CN to verify "the server certificates during the handshake"
	//   (https://tls.mbed.org/kb/how-to/use-sni)
	//
	// All examples that use this call are targeting the client side.
	// I did not find a single server example calling it.
	// But astonishingly, it does exactly what we want here:
	// Of course, the server does not send the SNI, that is only done by clients.
	// But the certificate checking part still seems to work!
	// As a result, this call forces the client CN to be the expected one.
	mbedtls_ssl_set_hostname(&ctx->ssl, expected_cn);

	// Hook the context's IO.
	// The context we pass will be the first argument of the send / recv calls.
	mbedtls_ssl_set_bio(&ctx->ssl, send_recv_ctx, send_data_func, NULL, recv_data_func);
}

void ssl_ctx_destroy(ssl_ctx* ctx)
{
	// Free all our stuff.
	mbedtls_ssl_free(&ctx->ssl);
	mbedtls_ssl_config_free(&ctx->config);
	mbedtls_x509_crt_free(&ctx->ca_crt);
	mbedtls_x509_crt_free(&ctx->srv_crt);
	mbedtls_pk_free(&ctx->srv_keys);
	mbedtls_ctr_drbg_free(&ctx->rng);
	mbedtls_entropy_free(&ctx->entropy);
}

const char* ssl_ctx_error_msg(int err)
{
	if (!err)
	{
		return "Success";
	}

	static __thread char error_buf[256];
	mbedtls_strerror(err, error_buf, sizeof(error_buf));

	return error_buf;
}

int ssl_ctx_perform_handshake(ssl_ctx* ctx)
{
	// Perform the SSL handshake.
	int err = mbedtls_ssl_handshake(&ctx->ssl);

	// If an error has occurred, reset the context.
	if (err)
	{
		mbedtls_ssl_session_reset(&ctx->ssl);
	}

	// Return the error back to the caller.
	return err;
}

int ssl_ctx_send(ssl_ctx* ctx, const unsigned char* data, size_t len)
{
	size_t bytes_written = 0;

	while (len > 0)
	{
		int result = mbedtls_ssl_write(&ctx->ssl, &data[bytes_written], len);

		// If the result is negative, it indicates an error.
		if (result < 0)
		{
			// Reset the context and return the error back to the caller.
			mbedtls_ssl_session_reset(&ctx->ssl);
			return result;
		}

		// Otherwise, the result indicates the number of bytes that has been sent.
		bytes_written += (size_t)result;
		len -= (size_t)result;
	}

	return 0;
}

int ssl_ctx_recv(ssl_ctx* ctx, unsigned char* data, size_t len)
{
	size_t bytes_read = 0;

	while (len > 0)
	{
		int result = mbedtls_ssl_read(&ctx->ssl, &data[bytes_read], len);

		// If the result is negative, it indicates an error.
		if (result < 0)
		{
			// Reset the context and return the error back to the caller.
			mbedtls_ssl_session_reset(&ctx->ssl);
			return result;
		}

		// If the result is 0, the transport layer has been closed.
		if (result == 0)
		{
			// Reset the context and return the info back to the caller.
			mbedtls_ssl_session_reset(&ctx->ssl);
			return SSL_CTX_TRANSPORT_CLOSED;
		}

		// Otherwise, the result indicates the number of bytes that has been sent.
		bytes_read += (size_t)result;
		len -= (size_t)result;
	}

	return 0;
}

void ssl_ctx_close_connection(ssl_ctx* ctx)
{
	mbedtls_ssl_close_notify(&ctx->ssl);
	mbedtls_ssl_session_reset(&ctx->ssl);
}
