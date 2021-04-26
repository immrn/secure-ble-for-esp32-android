#include "sdu_queue.h"


uint8_t sdu_queue_init(sdu_queue* queue, uint8_t length){
    queue->storage_area = (struct os_mbuf**)malloc(sizeof(struct os_mbuf*) * length);
    if(queue->storage_area == NULL){
        return SDU_QUEUE_ENOMEM;
    }
    queue->length = length;
    queue->free_nodes = length;
    // Set the referecens to NULL
    for(int i = 0; i < queue->length; i++){
        queue->storage_area[i] = NULL;
    }
    return 0;
}

uint8_t sdu_queue_add(sdu_queue* queue, struct os_mbuf* sdu){
    for(int i = 0; i < queue->length; i++){
        // Check if the loop reached the first unused element of the queue
        if(queue->storage_area[i] == NULL){
            queue->storage_area[i] = sdu;
            queue->free_nodes--;
            return 0;
        }
    }
    return SDU_QUEUE_EQUEUEFULL;
}

struct os_mbuf* sdu_queue_get(sdu_queue* queue){
    // Get the front element of the queue
    struct os_mbuf* front = queue->storage_area[0];

    for(int i = 0; i < queue->length; i++){
        // Check if the loop reached the end of queue
        if(i == queue->length-1){
            queue->storage_area[i] = NULL;
            break;
        }
        // Check if the loop already reached the last used element of the queue
        else if(queue->storage_area[i+1] == NULL){
            queue->storage_area[i] = NULL;
            break;
        }
        // Shift the references
        else{
            queue->storage_area[i] = queue->storage_area[i+1];
        }
    }

    if(front != NULL){
        queue->free_nodes++;
    }

    return front;
}

void sdu_queue_print(sdu_queue* queue){
    printf("Start printing SDU queue:\n");

    for(int i = 0; i < queue->length; i++){
        printf("Element %d:\n", i);
        if(queue->storage_area[i] != NULL){
            print_mbuf_as_string(queue->storage_area[i]);
        }
    }

    printf("Finished printing SDU queue!\n");
}