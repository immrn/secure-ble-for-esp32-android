#include "subscription.h"

#include <stdio.h>
#include "esp_log.h"
#include "esp_err.h"
// #include "esp_spiffs.h" TODO rm?
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "mbedtls/pk.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "app_config.h"
#include "app_l2cap.h"
#include "app_tags.h"



/*** Server-sided subscription process ***/

#ifdef ENDPOINT_ROLE_SERVER

int read_subscription_part(ssl_ctx* ctx, unsigned char* buf, uint16_t max_len, uint16_t* out_len){
	int err;
	uint16_t len;
	
	// Read the length.
	printf("RECEIVING LENGTH\n");
	err = ssl_ctx_recv(ctx, (unsigned char*)&len, sizeof(len));

	printf("Length = %d, max = %d\n", len, max_len);
	if (err || (len > max_len)){
		printf("err %i or len > max_len\n", err);
		return 1;
	}
	printf("Length = %d\n", len);

	// Read the data.
	printf("RECEIVING DATA\n");
	err = ssl_ctx_recv(ctx, buf, len);

	if (err){
		printf("err %i\n", err);
		return 1;
	}

	printf("Data:\n");
	for(int i = 0; i < len; i++){
		printf("%c", buf[i]);
	}
	printf("\n");

	*out_len = len;
	return 0;
}

int verify_subscription(ssl_ctx* ctx){
	// TODO: Right now, this has the following structure:
	// - 2 bytes: Payload length
	// - n bytes: Payload
	// - 2 bytes: signature length
	// - n bytes: signature
	// - 2 bytes: Signer certificate length (including null terminator)
	// - n bytes: Signer certificate (must be null-terminated, signed by CA, CN must be equal to "fb_steigtum_backend_subscript")

	int err;

	// Read the payload.
	unsigned char* payload_buf = (unsigned char*)malloc(sizeof(unsigned char) * MAX_PAYLOAD_LEN);
	assert(payload_buf != NULL);
	uint16_t payload_len;

	err = read_subscription_part(ctx, payload_buf, MAX_PAYLOAD_LEN, &payload_len);
	if(err){
		printf("Failed to read payload.\n");
		free(payload_buf);
		return 1;
	}

	printf("Payload length: %zu bytes\n", payload_len);

	// Hash the payload.
	unsigned char* hash = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	assert(hash != NULL);
	err = mbedtls_sha256_ret(payload_buf, payload_len, hash, 0);

	if(err){
		printf("Failed to hash payload: %s\n", ssl_ctx_error_msg(err));
		free(payload_buf);
		free(hash);
		return 1;
	}

	// Read the signature.
	unsigned char* signature_buf = (unsigned char*)malloc(sizeof(unsigned char) * 512);
	assert(signature_buf != NULL);
	uint16_t signature_len;

	err = read_subscription_part(ctx, signature_buf, 512, &signature_len);
	if(err){
		printf("Failed to read signature.\n");
		free(payload_buf);
		free(hash);
		free(signature_buf);
		return 1;
	}

	printf("Signature length: %zu bytes\n", signature_len);

	// Read the signer certificate.
	unsigned char* signer_crt_buf = (unsigned char*)malloc(sizeof(unsigned char) * 4096);
	assert(signer_crt_buf != NULL);
	uint16_t signer_crt_len;

	read_subscription_part(ctx, signer_crt_buf, 4096, &signer_crt_len);
	if(err){
		printf("Failed to read signer certificate.\n");
		free(payload_buf);
		free(hash);
		free(signature_buf);
		free(signer_crt_buf);
		return 1;
	}

	printf("Signer certificate length: %zu bytes\n", signer_crt_len);

	// Parse the signer certificate.
	mbedtls_x509_crt signer_crt;
	mbedtls_x509_crt_init(&signer_crt);

	err = mbedtls_x509_crt_parse(&signer_crt, signer_crt_buf, signer_crt_len);
	if(err){
		printf("Failed to parse signer certificate: %s\n", ssl_ctx_error_msg(err));
		mbedtls_x509_crt_free(&signer_crt);
		free(payload_buf);
		free(hash);
		free(signature_buf);
		free(signer_crt_buf);
		return 1;
	}

	// Verify the signer certificate.
	uint32_t flags;
	err = mbedtls_x509_crt_verify(&signer_crt, &ctx->ca_crt, NULL, EXPECTED_COMMON_NAME_SUBSCRIPTION, &flags, NULL, NULL);

	if(err){
		printf("Failed to validate signer certificate: %s\n", ssl_ctx_error_msg(err));
		mbedtls_x509_crt_free(&signer_crt);
		free(payload_buf);
		free(hash);
		free(signature_buf);
		free(signer_crt_buf);
		return 1;
	}

	// Verify the signature using the certificate's public key context and free the certificate.
	err = mbedtls_pk_verify(&signer_crt.pk, MBEDTLS_MD_SHA256, hash, 32, signature_buf, signature_len);
	mbedtls_x509_crt_free(&signer_crt);
	free(hash);
	free(signature_buf);
	free(signer_crt_buf);

	if(err){
		printf("Failed to verify signature: %s\n", ssl_ctx_error_msg(err));
		free(payload_buf);
		return 1;
	}

	// TODO: Pass the valid payload to read its content!

	free(payload_buf);

	return 0;
}

#endif /* ENDPOINT_ROLE_SERVER */



/*** Client-sided subscription process ***/

#ifdef ENDPOINT_ROLE_CLIENT

void read_file(char* path, unsigned char* buf, uint16_t max_len, uint16_t* out_len){
	// This is used to bypass the usage of the back end server
	// (we only want to "emulate" the back end server here).
	// Do not use this for a real application but look at
	// the section "Application Details" in README.md to
	// get to know what the Client should do instead.

	int cur_char = 0;
	FILE* file;

	file = fopen(path, "r");
	if(file == NULL){
		ESP_LOGE(SPIFFS_TAG, "Can't open file %s", path);
		assert(0);
	}

	// Read from file and count the chars.
	for(uint16_t i = 0; i < max_len; i++){
		cur_char = fgetc(file);
		if(cur_char == EOF){
			*out_len = i;
			break;
		}
		buf[i] = (unsigned char)cur_char;
	}

	printf("file: %s\nlen: %d\ndata:\n%s\n", path, *out_len, buf);

	fclose(file);
	return;
}



int send_subscription(ssl_ctx* ctx){
	// This is used to bypass the usage of the back end server
	// (we only want to "emulate" the back end server here).
	// Do not use this for a real application but look at
	// the section "Application Details" in README.md to
	// get to know what the Client should do instead.

	int err;
	uint16_t file_len;
	
	// Read the payload.
	unsigned char* payload_buf = (unsigned char*)malloc(sizeof(unsigned char) * MAX_PAYLOAD_LEN);
	assert(payload_buf != NULL);
	read_file("/spiffs/crypto/payload.txt", payload_buf, MAX_PAYLOAD_LEN, &file_len);

	// Send the payload length.
	err = ssl_ctx_send(ctx, (unsigned char*)&file_len, sizeof(file_len));
	if(err){
		printf("Failed to send the payload length: %s\n", ssl_ctx_error_msg(err));
		free(payload_buf);
		return 1;
	}

	// Send the payload.
	err = ssl_ctx_send(ctx, payload_buf, file_len);
	if(err){
		printf("Failed to send the payload: %s\n", ssl_ctx_error_msg(err));
		free(payload_buf);
		return 1;
	}

	// Hash the payload.
	unsigned char* hash = (unsigned char*)malloc(sizeof(unsigned char) * 32);
	assert(hash != NULL);
	err = mbedtls_sha256_ret(payload_buf, file_len, hash, 0);
	free(payload_buf);

	if(err){
		printf("Failed to hash the payload: %s\n", ssl_ctx_error_msg(err));
		free(hash);
		return 1;
	}

	// Read the signer key (private key).
	mbedtls_pk_context signer_key;
	mbedtls_pk_init(&signer_key);

	err = mbedtls_pk_parse_keyfile(&signer_key, "/spiffs/crypto/backend_subscript.key", NULL);
	if(err){
		printf("Failed to parse the private subscription key from file: %s\n", ssl_ctx_error_msg(err));
		mbedtls_pk_free(&signer_key);
		free(hash);
		return 1;
	}

	// Create the signature of the hash using the signer key.
	unsigned char* signature_buf = (unsigned char*)malloc(sizeof(unsigned char) * 512);
	assert(signature_buf != NULL);
	uint16_t signature_len;

	err = mbedtls_pk_sign(&signer_key, MBEDTLS_MD_SHA256, hash, 32, signature_buf, (size_t*)&signature_len, NULL, NULL);
	free(hash);
	mbedtls_pk_free(&signer_key);

	if(err){
		printf("Failed to sign the hash of the payload: %s\n", ssl_ctx_error_msg(err));
		mbedtls_pk_free(&signer_key);
		free(hash);
		free(signature_buf);
		return 1;
	}

	// Send the signature length.
	err = ssl_ctx_send(ctx, (unsigned char*)&signature_len, sizeof(signature_len));
	if(err){
		printf("Failed to send the signature length: %s\n", ssl_ctx_error_msg(err));
		free(signature_buf);
		return 1;
	}

	// Send the signature.
	err = ssl_ctx_send(ctx, signature_buf, signature_len);
	free(signature_buf);

	if(err){
		printf("Failed to send the signature: %s\n", ssl_ctx_error_msg(err));
		return 1;
	}

	// Read the signer certificate.
	unsigned char* signer_crt_buf = (unsigned char*)malloc(sizeof(unsigned char) * 4096);
	assert(signer_crt_buf != NULL);
	uint16_t signer_crt_len;
	read_file("/spiffs/crypto/backend_subscript.crt", signer_crt_buf, 4096, &signer_crt_len);

	// Add the NULL byte/terminator to the end of the signer certificate (PEM).
	signer_crt_len++;
	signer_crt_buf[signer_crt_len-1] = 0x0;

	// Send the length of the signer certificate.
	err = ssl_ctx_send(ctx, (unsigned char*)&signer_crt_len, sizeof(signer_crt_len));
	if(err){
		printf("Failed to send the length of the signer certificate: %s", ssl_ctx_error_msg(err));
		free(signer_crt_buf);
		return 1;
	}

	// Send the signer certificate.
	err = ssl_ctx_send(ctx, signer_crt_buf, signer_crt_len);
	free(signer_crt_buf);

	if(err){
		printf("Failed to send the signer certificate: %s", ssl_ctx_error_msg(err));
		return 1;
	}

	return 0;
}

#endif /* ENDPOINT_ROLE_CLIENT */



/*** General subscription process ***/

void test_mbedtls_1(io_ctx* io, ssl_ctx* ctx){
    int err;

    // Accept clients.
	for (;;){
        // TODO: solve this better
        // Await L2CAP connection
        while(l2cap_conns[0].coc_list.slh_first == NULL ){
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
        io->conn = &l2cap_conns[0];
        io->coc_idx = 0;

        ESP_LOGI(MBEDTLS_TAG, "----- Starting TLS Handshake -----");

		// Try to perform a successful SSL handshake.
		err = ssl_ctx_perform_handshake(ctx);

		if(err != 0){
			ESP_LOGE(MBEDTLS_TAG, "Failed to perform SSL handshake: %s\n", ssl_ctx_error_msg(err));
            assert(0);
			// TODO: rm assert
			// l2cap_disconnect(io->conn->handle, io->coc_idx);
			// continue;
		}

		ESP_LOGI(MBEDTLS_TAG, "----- TLS Handshake successful -----\n");

		sdu_queue_print(&sdu_queue_rx);
		vTaskDelay(3000 / portTICK_PERIOD_MS);
		sdu_queue_print(&sdu_queue_rx);

		printf("----- Starting subscription exchange -----\n");

#ifdef ENDPOINT_ROLE_SERVER

		// Receive and verify the signed subscription.
		err = verify_subscription(ctx);
		if(err){
			ssl_ctx_close_connection(ctx);
			l2cap_disconnect(io->conn->handle, io->coc_idx);
			assert(0);
			//continue; TODO
		}

#else /* Client */

		// It's a client.
		// Send the signed subscription.
		err = send_subscription(ctx);
		if(err){
			ssl_ctx_close_connection(ctx);
			l2cap_disconnect(io->conn->handle, io->coc_idx);
			assert(0);
			// continue; TODO
		}

#endif /* ENDPOINT_ROLE */

		printf("----- Subscription exchange was successful -----\n");

		// Close the connection.
		ssl_ctx_close_connection(ctx);

		// TODO

		break;
	}
}
