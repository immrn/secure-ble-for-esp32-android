#include "app_ssl.h"

#include "app_tags.h"
#include "esp_log.h"
#include "esp_err.h"
#include "os/os_mbuf.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509.h"
#include "freertos/task.h"

#include "app_l2cap.h"
#include "app_config.h"



// TODO DEBUG remove: Delay before sending. Comment to ignore it.
// #define SEND_DELAY_MS 3000



int send_data(void* ctx, const unsigned char* data, size_t len){
    int res;
    uint16_t compatible_len;
    io_ctx* io = ctx;

    // l2cap_send would fail if len > L2CAP_COC_MTU.
    if(len > L2CAP_COC_MTU){
        compatible_len = L2CAP_COC_MTU;
    }else{
        compatible_len = (uint16_t)len;
    }

    // Try to send. (l2cap_send blocks)
    ESP_LOGI(MBEDTLS_TAG, "Want to send %d bytes! (task handle = %p)", compatible_len, xTaskGetCurrentTaskHandle());

#if SEND_DELAY_MS
    // TODO DEBUG remove delay
    printf("Delay... ");
    vTaskDelay(SEND_DELAY_MS / portTICK_PERIOD_MS);
    printf("finished!\n");
#endif

    res = l2cap_send(io->conn->handle, io->coc_idx, data, compatible_len);

    // If sending was successful, return the bytes that were sent.
    if(res == 0 || res == BLE_HS_ESTALLED){
		return compatible_len;
    }

    // Sending failed
    ESP_LOGE(MBEDTLS_TAG, "Sending failed!");
    return -1;
}

int recv_data(void* ctx, unsigned char* data, size_t len, uint32_t timeout_msec){
    int res;
    io_ctx* io = ctx;
    struct os_mbuf* sdu;
    struct l2cap_coc_node* coc;
	static int count = 0; // TODO DEBUG remove

    ESP_LOGI(MBEDTLS_TAG, "Want to read/recv %u bytes!", len);
	ESP_LOGI(MBEDTLS_TAG, "core id = %d, task handle = %p", xPortGetCoreID(), xTaskGetCurrentTaskHandle());
    sdu_queue_print(&sdu_queue_rx);

    // Check if the RX Buffer (sdu_os_mbuf_pool_rx) is empty.
	// Otherwise the RX Buffer contains unread data already and we skip the IF-Scope.
    sdu = sdu_queue_get(&sdu_queue_rx);
    if(sdu == NULL){
        // sdu_queue_rx is empty -> sdu_os_mbuf_pool_rx is empty -> we have to receive data from the peer

        // Get the current COC.
        coc = l2cap_coc_find_by_idx(io->conn, io->coc_idx);
        assert(coc != NULL);

        // Make the timeout value compatible for the upcoming semaphore
        if(timeout_msec == 0){
            ESP_LOGI(MBEDTLS_TAG, "Set receive timeout to infinite.");
            timeout_msec = portMAX_DELAY;
        }else{
            timeout_msec = timeout_msec / portTICK_PERIOD_MS;
        }

        // Send the peer the command to send data
        sdu = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool_rx, 0);
        assert(sdu != NULL);

        ESP_LOGI(MBEDTLS_TAG, "RECEIVE READY!");
        res = ble_l2cap_recv_ready(coc->chan, sdu);
        assert(res == 0);

        // Await the incoming data
        ESP_LOGI(MBEDTLS_TAG, "Try to take semaphore"); // TODO DEBUG remove
        res = xSemaphoreTake(coc->received_data_semaphore, portMAX_DELAY /*TODO DEBUG set to timeout_msec*/);
        ESP_LOGI(MBEDTLS_TAG, "Received semaphore"); // TODO DEBUG remove
        if(res != pdTRUE){
            // Semaphore wasn't obtained
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }

        // Received the semaphore. The SDU was added to sdu_os_mbuf_pool_rx
        // and as reference to sdu_queue_rx by l2cap_coc_recv().
    }

    // Read the RX Buffer and free resources of the buffer if possible.
	ESP_LOGI(MBEDTLS_TAG, "Reading from buffer...");
	res = l2cap_read_rx_buffer(data, len, &sdu_queue_rx);

	ESP_LOGI(MBEDTLS_TAG, "Did read %d bytes from buffer.\n", res);
	sdu_queue_print(&sdu_queue_rx);

	// Return the bytes read
	return res;
}

int read_subscription_part(ssl_ctx* ctx, unsigned char* buf, size_t max_len, size_t* out_len){
	// Length
	uint16_t len;
	int err = ssl_ctx_recv(ctx, (unsigned char*)&len, sizeof(len));

	if (err || (len > max_len))
	{
		printf("err %i or len > max_len\n", err);
		return 0;
	}

	// Data
	err = ssl_ctx_recv(ctx, buf, len);

	if (err)
	{
		printf("err %i\n", err);
		return 0;
	}

	*out_len = len;
	return 1;
}

int verify_subscription(ssl_ctx* ctx){
	// TODO: Right now, this has the following structure:
	// - 2 bytes: Payload length
	// - n bytes: Payload
	// - 2 bytes: signature length
	// - n bytes: signature
	// - 2 bytes: Signer certificate length (including null terminator)
	// - n bytes: Signer certificate (must be null-terminated, signed by CA, CN must be equal to "fb_steigtum_backend_subscript")

	// Read the payload.
	unsigned char payload_buf[1024];
	size_t payload_len;

	if (!read_subscription_part(ctx, payload_buf, sizeof(payload_buf), &payload_len))
	{
		printf("Failed to read payload.\n");
		return 0;
	}

	printf("Payload length: %zu bytes\n", payload_len);

	// Hash the payload.
	unsigned char hash[32];
	int err = mbedtls_sha256_ret(payload_buf, payload_len, hash, 0);

	if (err)
	{
		printf("Failed to hash payload: %s\n", ssl_ctx_error_msg(err));
		return 0;
	}

	// Read the signature.
	unsigned char signature_buf[512];
	size_t signature_len;

	if (!read_subscription_part(ctx, signature_buf, sizeof(signature_buf), &signature_len))
	{
		printf("Failed to read signature.\n");
		return 0;
	}

	printf("Signature length: %zu bytes\n", signature_len);

	// Read the signer certificate.
	unsigned char signer_crt_buf[4096];
	size_t signer_crt_len;

	if (!read_subscription_part(ctx, signer_crt_buf, sizeof(signer_crt_buf), &signer_crt_len))
	{
		printf("Failed to read signer certificate.\n");
		return 0;
	}

	printf("Signer certificate length: %zu bytes\n", signer_crt_len);

	// Parse the signer certificate.
	mbedtls_x509_crt signer_crt;
	mbedtls_x509_crt_init(&signer_crt);

	err = mbedtls_x509_crt_parse(&signer_crt, signer_crt_buf, signer_crt_len);

	if (err)
	{
		printf("Failed to parse signer certificate: %s\n", ssl_ctx_error_msg(err));
		mbedtls_x509_crt_free(&signer_crt);

		return 0;
	}

	// Verify the signer certificate.
	uint32_t flags;
	err = mbedtls_x509_crt_verify(&signer_crt, &ctx->ca_crt, NULL, "fb_steigtum_backend_subscript", &flags, NULL, NULL);

	if (err)
	{
		printf("Failed to validate signer certificate: %s\n", ssl_ctx_error_msg(err));
		mbedtls_x509_crt_free(&signer_crt);

		return 0;
	}

	// Verify the signature using the certificate's public key context and free the certificate.
	err = mbedtls_pk_verify(&signer_crt.pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature_buf, signature_len);
	mbedtls_x509_crt_free(&signer_crt);

	if (err)
	{
		printf("Failed to verify signature: %s\n", ssl_ctx_error_msg(err));
		return 0;
	}

	// TODO: Return the valid subscription!

	return 1;
}

void test_mbedtls_1(io_ctx* io, ssl_ctx* ssl_context){
    int err;

#if MYNEWT_VAL(BLE_HS_DEBUG)
    printf("BLE DEBUG ENABLED\n");
#endif

    // Accept clients.
	for (;;)
	{
        // TODO: solve this better
        // Await L2CAP connection
        while(l2cap_conns[0].coc_list.slh_first == NULL ){
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }
        io->conn = &l2cap_conns[0];
        io->coc_idx = 0;

        ESP_LOGI(MBEDTLS_TAG, "----- Starting TLS Handshake -----");

		// Try to perform a successful SSL handshake.
		err = ssl_ctx_perform_handshake(ssl_context);

		if (err != 0)
		{
			ESP_LOGE(MBEDTLS_TAG, "Failed to perform SSL handshake: %s\n", ssl_ctx_error_msg(err));
            assert(0); // TODO continue;
		}

		// // Receive and verify the signed subscription.
		// if (!verify_subscription(&ctx))
		// {
		// 	ssl_ctx_close_connection(&ctx);
		// 	close(new_sock);

		// 	continue;
		// }

		// Close the connection.
		ssl_ctx_close_connection(ssl_context);

        ESP_LOGI(MBEDTLS_TAG, "----- TLS Handshake successful -----\n");

		break;
	}
}