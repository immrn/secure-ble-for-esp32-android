#include "app_l2cap_io_calls.h"

#include <stdio.h>

#include "app_tags.h"
#include "esp_log.h"
#include "esp_err.h"
#include "os/os_mbuf.h"
#include "freertos/task.h"
#include "mbedtls/ssl.h"

#include "app_io_ctx.h"
#include "app_l2cap.h"
#include "app_config.h"



// Callbacks for mbedtls

int l2cap_io_send_data(void* ctx, const unsigned char* data, size_t len){
    int res;
    uint16_t compatible_len;
    io_ctx* io = ctx;

    // l2cap_send would fail if len > L2CAP_COC_MTU.
    if(len > L2CAP_COC_MTU){
        compatible_len = L2CAP_COC_MTU;
    }else{
        compatible_len = (uint16_t)len;
    }

    ESP_LOGI(L2CAP_TAG, "Want to send %d bytes!", compatible_len);
    // TODO DEBUG rm this later
    TaskHandle_t curr_task = xTaskGetCurrentTaskHandle();
	ESP_LOGI(L2CAP_TAG, "core id = %d, task handle = %p, task name = %s\n", xPortGetCoreID(), curr_task, pcTaskGetName(curr_task));

    // Try to send. (l2cap_send is blocking)
    res = l2cap_send(io->conn->handle, io->coc_idx, data, compatible_len);

    // If sending was successful, return the bytes that were sent.
    if(res == 0 || res == BLE_HS_ESTALLED){
        return compatible_len;
    }

    // Sending failed.
    ESP_LOGE(L2CAP_TAG, "Sending failed!");
    return -1;
}

int l2cap_io_recv_data(void* ctx, unsigned char* data, size_t len, uint32_t timeout_msec){
    int res;
    io_ctx* io = ctx;
    struct os_mbuf* sdu;
    struct l2cap_coc_node* coc;

    ESP_LOGI(L2CAP_TAG, "Want to read/recv %u bytes!", len);
	// TODO DEBUG rm this later
    TaskHandle_t curr_task = xTaskGetCurrentTaskHandle();
	ESP_LOGI(L2CAP_TAG, "core id = %d, task handle = %p, task name = %s", xPortGetCoreID(), curr_task, pcTaskGetName(curr_task));

    sdu_queue_print(&sdu_queue_rx);

	// Get the current COC.
	coc = l2cap_coc_find_by_idx(io->conn, io->coc_idx);
	assert(coc != NULL);

    // Check if the RX Buffer (sdu_os_mbuf_pool_rx) is empty.
	// Otherwise the RX Buffer contains unread data already and we skip the IF-Scope.
    sdu = sdu_queue_get(&sdu_queue_rx);
    if(sdu == NULL){
        // sdu_queue_rx is empty -> sdu_os_mbuf_pool_rx is empty -> we have to receive data from the peer.

        // Make the timeout value compatible for the upcoming semaphore.
        if(timeout_msec == 0){
            ESP_LOGI(L2CAP_TAG, "Set receive timeout to infinite.");
            timeout_msec = portMAX_DELAY;
        }else{
            timeout_msec = timeout_msec / portTICK_PERIOD_MS;
        }

        // Await the incoming data.
        ESP_LOGI(L2CAP_TAG, "Waiting for next incoming SDU...");
		xSemaphoreGive(coc->want_data_semaphore);
        res = xSemaphoreTake(coc->received_data_semaphore, timeout_msec);
        if(res != pdTRUE){
            // Semaphore wasn't obtained.
			ESP_LOGI(L2CAP_TAG, "Timeout: Didn't receive a SDU.");
            return MBEDTLS_ERR_SSL_TIMEOUT;
        }
		ESP_LOGI(L2CAP_TAG, "Received a SDU.");

        // Received the semaphore. The SDU was added to sdu_os_mbuf_pool_rx
        // and as reference to sdu_queue_rx by l2cap_coc_recv().
    }

    // Read the RX Buffer and free resources of the buffer if possible.
	ESP_LOGI(L2CAP_TAG, "Reading from buffer...");
	res = l2cap_read_rx_buffer(&sdu_queue_rx, coc, data, len);

	ESP_LOGI(L2CAP_TAG, "Did read %d bytes from buffer.", res);
	sdu_queue_print(&sdu_queue_rx);
	printf("\n");

	// Return the bytes read.
	return res;
}
