#include <errno.h>
#include "os/os_mbuf.h"
#include "os/os_mempool.h"
#include "host/ble_hs.h"
#include "../src/ble_hs_priv.h"
#include "host/ble_l2cap.h"
#include "freertos/semphr.h"

#include "app_config.h"
#include "sdu_queue.h"
#include "app_misc.h"



#define L2CAP_COC_BUF_COUNT_RX (6 * MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM))
#define L2CAP_COC_BUF_COUNT_TX (2 * MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM))
// The block size in a os_mbuf_pool and also in a os_mempool in bytes = os_mbuf.om_len + 24. Because we want a SDU to store exactly one MTU, we have to make sure that os_mbuf.om_len = MTU. This is why the block size value shall equal MTU + 24.
#define L2CAP_COC_MEM_BLOCK_SIZE (L2CAP_COC_MTU + 24)

#define INT_TO_PTR(x)     (void *)((intptr_t)(x))
#define PTR_TO_INT(x)     (int) ((intptr_t)(x))

struct l2cap_coc_node{
    SLIST_ENTRY(l2cap_coc_node) next;
    struct ble_l2cap_chan *chan;
    SemaphoreHandle_t unstalled_semaphore;
    SemaphoreHandle_t want_data_semaphore;
    SemaphoreHandle_t received_data_semaphore;
    SemaphoreHandle_t sdu_queue_removed_element_semaphore;
};

SLIST_HEAD(l2cap_coc_list, l2cap_coc_node);

struct l2cap_conn {
    uint16_t handle;
    struct l2cap_coc_list coc_list;
};

struct l2cap_conn l2cap_conns[MYNEWT_VAL(BLE_MAX_CONNECTIONS)];
int l2cap_conns_num;

os_membuf_t l2cap_coc_conn_mem[OS_MEMPOOL_SIZE(MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM), sizeof(struct l2cap_coc_node))];
struct os_mempool l2cap_coc_conn_pool;

// RX memory pools
os_membuf_t l2cap_sdu_coc_mem_rx[OS_MEMPOOL_SIZE(L2CAP_COC_BUF_COUNT_RX, L2CAP_COC_MTU)];
struct os_mbuf_pool sdu_os_mbuf_pool_rx;
struct os_mempool sdu_coc_mbuf_mempool_rx;
// RX SDU queue to track the order of the SDUs/mbufs in the sdu_os_mbuf_pool_rx
sdu_queue sdu_queue_rx;

// TX memory pools
os_membuf_t l2cap_sdu_coc_mem_tx[OS_MEMPOOL_SIZE(L2CAP_COC_BUF_COUNT_TX, L2CAP_COC_MTU)];
struct os_mbuf_pool sdu_os_mbuf_pool_tx;
struct os_mempool sdu_coc_mbuf_mempool_tx;


int l2cap_conn_find_idx(uint16_t handle);

struct l2cap_conn *l2cap_conn_find(uint16_t handle);

struct l2cap_conn *l2cap_conn_add(struct ble_gap_conn_desc *desc);

void l2cap_conn_delete_idx(int conn_idx);

/*** l2cap coc ***/

struct l2cap_coc_node* l2cap_coc_find(struct l2cap_conn* conn, struct ble_l2cap_chan* chan);

struct l2cap_coc_node* l2cap_coc_find_by_idx(struct l2cap_conn* conn, uint16_t coc_idx);

int l2cap_coc_add(uint16_t conn_handle, struct ble_l2cap_chan *chan);

void l2cap_coc_remove(uint16_t conn_handle, struct ble_l2cap_chan *chan);

void l2cap_coc_recv(uint16_t conn_handle, struct ble_l2cap_chan *chan, struct os_mbuf *sdu);

int l2cap_coc_accept(uint16_t conn_handle, uint16_t peer_mtu, struct ble_l2cap_chan *chan);

void l2cap_coc_unstalled(uint16_t conn_handle, struct ble_l2cap_chan *chan);

int l2cap_create_srv(uint16_t psm, uint16_t mtu, int accept_response);

int l2cap_connect(uint16_t conn_handle, uint16_t psm, uint16_t mtu, uint8_t num);

int l2cap_disconnect(uint16_t conn_handle, uint16_t coc_idx);

int l2cap_reconfig(uint16_t conn_handle, uint16_t mtu, uint8_t num, uint8_t idxs[]);

int l2cap_send(uint16_t conn_handle, uint16_t coc_idx, const unsigned char* data, uint16_t len);

/*** Read Buffer (mbuf pool) ***/

/*
 *  @brief          Reads data of the SDUs of a os_mbuf_pool. Access to the SDUs is acquired through the sdu_queue.
 *
 *  @param queue    Initialized queue.
 *  @param coc      The currenct COC.
 *  @param data     Buffer to write the received data to.
 *  @param len      Length of the data to read.
 *  
 * 
 *  @return         Returns number of bytes read.
 */
size_t l2cap_read_rx_buffer(sdu_queue* queue, struct l2cap_coc_node* coc, unsigned char* data, size_t len);

/*** General ***/

int on_l2cap_event(struct ble_l2cap_event *event, void *arg);

// TODO REMOVE
int l2cap_send_old_from_btshell(uint16_t conn_handle, uint16_t coc_idx, const unsigned char* data, uint16_t len);