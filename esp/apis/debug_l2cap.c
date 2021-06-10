#include "debug_l2cap.h"

#include <string.h>

#include "app_l2cap_io_calls.h"
#include "app_l2cap.h"



// Debugging stuff, TODO maybe delete

int debug_l2cap_send(io_ctx* io, const unsigned char* data, size_t len){
	size_t bytes_written = 0;

	while (len > 0){
		int result = l2cap_io_send_data(io, &data[bytes_written], len);

		// If the result is negative, it indicates an error.
		if(result < 0){
			assert(0);
		}

		// Otherwise, the result indicates the number of bytes that has been sent.
		bytes_written += (size_t)result;
		len -= (size_t)result;
	}

	return 0;
}

int debug_l2cap_recv(io_ctx* io, unsigned char* data, size_t len){
	size_t bytes_read = 0;

	while (len > 0){
		int result = l2cap_io_recv_data(io, &data[bytes_read], len, 0);

		// If the result is negative, it indicates an error.
		if(result < 0){
            assert(0);
		}

		// If the result is 0, the transport layer has been closed.
		if (result == 0){
			return 0;
		}

		// Otherwise, the result indicates the number of bytes that has been sent.
		bytes_read += (size_t)result;
		len -= (size_t)result;
	}

	return 0;
}

static int message_len = 6;
static int packet_count = 5;

int test_l2cap_tx(io_ctx* io){
	printf("Test L2CAP transmission.\n");

    // Await L2CAP connection.
    while(l2cap_conns[0].coc_list.slh_first == NULL ){
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

	// Set I/O context.
    io->conn = &l2cap_conns[0];
    io->coc_idx = 0;

    // Create message.
    char* message = (char*)malloc(sizeof(char) * message_len);
	assert(message != NULL);
    strcpy(message, "Hello!");

	// Send message(s).
	for(int i = 0; i < packet_count; i++){
		debug_l2cap_send(io, (const unsigned char*) message, message_len);
	}

	free(message);

	return 0;
}

int test_l2cap_rx(io_ctx* io){
	// Await L2CAP connection.
    while(l2cap_conns[0].coc_list.slh_first == NULL ){
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    io->conn = &l2cap_conns[0];
    io->coc_idx = 0;

	vTaskDelay(3000 / portTICK_PERIOD_MS);

	char* message_buf = malloc(sizeof(char) * message_len);
	for(int i = 0; i < packet_count; i++){
		debug_l2cap_recv(io, (unsigned char*) message_buf, message_len);
		for(int j = 0; j < message_len; j++){
			printf("%c", message_buf[j]);
		}
		printf("\n");
	}

	free(message_buf);

	return 0;
}
