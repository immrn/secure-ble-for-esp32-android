#include <stdint.h>
#include "os/os_mbuf.h"

#include "app_misc.h"

// Error codes
#define SDU_QUEUE_ENOMEM 1 // Error while trying to allocate memory
#define SDU_QUEUE_EQUEUEFULL 2 // Queue is full and can't take more elements

/*
 *  @brief Static queue for SDUs (mbuf). This queue only holds the references, not the data itself. This queue can only be used as addition to manage the order of SDUs which usually should be stored in a os_mbuf_pool (os/os_mbuf.h).
 */
typedef struct{
    uint8_t length; // max amount of SDU nodes
    uint8_t free_nodes;
    struct os_mbuf** storage_area;
} sdu_queue;

/*
 *  @brief Initializes a static SDU queue.
 *
 *  @param queue    The declared queue you want to initialize.
 *  @param length   The amount of elements the queue can hold.
 * 
 *  @return 0 at success, otherwise a non-zero error code will be returned.
 */
uint8_t sdu_queue_init(sdu_queue* queue, uint8_t length);

/*
 *  @brief Add a SDU as a element (reference) to the back of a queue.
 *
 *  @param queue    The queue you want to add an element. The queue must be initialized by sdu_queue_init()
 *  @param sdu      The SDU you want to add as element (reference) to the queue.
 * 
 *  @return 0 at success, otherwise a non-zero error code will be returned.
 */
uint8_t sdu_queue_add(sdu_queue* queue, struct os_mbuf* sdu);

/*
 *  @brief Get the front element (reference) of the queue. The element will be removed (reference = NULL) and the queue rearranges itself.
 *  @param queue    The queue of which you want to get the front element (reference)
 *  
 *  @return The front element (reference) of the queue. If NULL is returned, the queue is empty.
 */
struct os_mbuf* sdu_queue_get(sdu_queue* queue);

/*
 *  @brief For debugging only.
 */
void sdu_queue_print(sdu_queue* queue);