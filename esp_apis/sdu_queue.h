#include <stdint.h>
#include "os/os_mbuf.h"

#include "app_config.h"
#include "app_misc.h"


#ifdef L2CAP_COC_MTU
#if (L2CAP_COC_MTU <= 256)
typedef uint8_t sdu_queue_offset_t;
#else
typedef uint16_t sdu_queue_offset_t;
#endif


// Error codes
#define SDU_QUEUE_ENOMEM        1 // Error while trying to allocate memory
#define SDU_QUEUE_EQUEUEFULL    2 // Queue was and is still full and can't take more elements
#define SDU_QUEUE_EQUEUEEMPTY   3 // Queue was and is still empty

/*
 *  @brief          Static queue that holds references pointing at SDUs (os_mbuf) . So this queue doen't contain the data itself. It can only be used as addition to manage the order of SDUs which usually should be stored in a os_mbuf_pool (os/os_mbuf.h).
 */
typedef struct{
    uint8_t length; // Max. amount of references pointing to SDUs (os_mbuf).
    uint8_t free_nodes; // Amount of unused references (these are pointing at NULL).
    sdu_queue_offset_t front_offset; // Offset of the front element / SDU.
    struct os_mbuf** storage_area;
} sdu_queue;


/*
 *  @brief          Initializes a static SDU queue.
 *
 *  @param queue    The declared queue you want to initialize.
 *  @param length   The amount of elements the queue can hold.
 * 
 *  @return         0 at success, otherwise a non-zero error code will be returned.
 */
uint8_t sdu_queue_init(sdu_queue* queue, uint8_t length);

/*
 *  @brief          Add a SDU as a element (reference) to the back of a queue.
 *
 *  @param queue    The queue you want to add an element. The queue must be initialized by sdu_queue_init()
 *  @param sdu      The SDU you want to add as element (reference) to the queue.
 * 
 *  @return         0 at success, otherwise a non-zero error code will be returned.
 */
uint8_t sdu_queue_add(sdu_queue* queue, struct os_mbuf* sdu);

/*
 *  @brief          Get the front element (reference) of the queue.
 *  @param queue    The queue of which you want to get the front element (reference).
 *  
 *  @return         The front element (reference) of the queue. NULL if the queue is empty.
 */
struct os_mbuf* sdu_queue_get(sdu_queue* queue);

/*
 *  @brief          Remove the front element of a queue (reference = NULL). The queue resets the front_offset and rearranges itself.
 *  @param queue    The queue of which you want to remove the front element (reference) off.
 *  
 *  @return         0 at success, otherwise a non-zero error code will be returned.
 */
uint8_t sdu_queue_remove(sdu_queue* queue);

/*
 *  @brief          Add a value to the offset of the front element.
 *
 *  @param queue    The queue of which you want to set the fronts offset.
 *  @param value    The value you want to add to the current offset of the front element.
 * 
 *  @return         0 at success, otherwise a non-zero error code will be returned.
 */
uint8_t sdu_queue_increase_offset(sdu_queue* queue, sdu_queue_offset_t value);

/*
 *  @brief          For debugging only.
 */
void sdu_queue_print(sdu_queue* queue);

#endif /* L2CAP_COC_MTU */