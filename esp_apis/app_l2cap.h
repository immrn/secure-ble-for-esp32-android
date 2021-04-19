#include <errno.h>
#include "os/os_mbuf.h"
#include "os/os_mempool.h"
#include "host/ble_hs.h"
#include "../src/ble_hs_priv.h"
#include "host/ble_l2cap.h"

#include "app_misc.h"


#define APP_CID 0xffff
#define L2CAP_COC_MTU 256
#define L2CAP_COC_BUF_COUNT (3 * MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM))

#define INT_TO_PTR(x)     (void *)((intptr_t)(x))
#define PTR_TO_INT(x)     (int) ((intptr_t)(x))

struct l2cap_coc_struct{
    SLIST_ENTRY(l2cap_coc_struct) next;
    struct ble_l2cap_chan *chan;
    bool stalled;
};

SLIST_HEAD(l2cap_coc_list, l2cap_coc_struct);

struct l2cap_conn {
    uint16_t handle;
    struct l2cap_coc_list coc_list;
};

struct l2cap_conn l2cap_conns[MYNEWT_VAL(BLE_MAX_CONNECTIONS)];
int l2cap_conns_num;

os_membuf_t l2cap_coc_conn_mem[OS_MEMPOOL_SIZE(MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM), sizeof(struct l2cap_coc_struct))];
struct os_mempool l2cap_coc_conn_pool;

os_membuf_t l2cap_sdu_coc_mem[OS_MEMPOOL_SIZE(L2CAP_COC_BUF_COUNT, L2CAP_COC_MTU)];
struct os_mbuf_pool sdu_os_mbuf_pool;
struct os_mempool sdu_coc_mbuf_mempool;



int l2cap_conn_find_idx(uint16_t handle);

struct l2cap_conn *l2cap_conn_find(uint16_t handle);

struct l2cap_conn *l2cap_conn_add(struct ble_gap_conn_desc *desc);

void l2cap_conn_delete_idx(int conn_idx);

/*** l2cap coc ***/

int l2cap_coc_add(uint16_t conn_handle, struct ble_l2cap_chan *chan);

void l2cap_coc_remove(uint16_t conn_handle, struct ble_l2cap_chan *chan);

void l2cap_coc_recv(struct ble_l2cap_chan *chan, struct os_mbuf *sdu);

int l2cap_coc_accept(uint16_t conn_handle, uint16_t peer_mtu, struct ble_l2cap_chan *chan);

void l2cap_coc_unstalled(uint16_t conn_handle, struct ble_l2cap_chan *chan);

int l2cap_create_srv(uint16_t psm, uint16_t mtu, int accept_response);

int l2cap_connect(uint16_t conn_handle, uint16_t psm, uint16_t mtu, uint8_t num);

int l2cap_disconnect(uint16_t conn_handle, uint16_t coc_idx);

int l2cap_reconfig(uint16_t conn_handle, uint16_t mtu, uint8_t num, uint8_t idxs[]);

int l2cap_send(uint16_t conn_handle, uint16_t coc_idx, const unsigned char* data, uint16_t len);

int on_l2cap_event(struct ble_l2cap_event *event, void *arg);

int l2cap_send_test(uint16_t conn_handle, uint16_t coc_idx, const unsigned char* data, uint16_t len, int iterator);