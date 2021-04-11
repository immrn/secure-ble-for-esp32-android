#include <stdio.h>
#include <stdint.h>

#include "os/os_mbuf.h"
#include "os/os_mempool.h"

#include "esp_nimble_hci.h"
#include "host/ble_hs.h"

/*** gap ***/

int adv_start(uint8_t own_addr_type, const ble_addr_t *direct_addr, int32_t duration_ms, const struct ble_gap_adv_params *params, bool restart);

int adv_stop(void);

static int adv_restart(struct ble_gap_event *event);

void print_addr(const void *addr);

void print_conn_desc(const struct ble_gap_conn_desc *desc);

void print_bytes(const uint8_t *bytes, int len);

static void print_adv_fields(const struct ble_hs_adv_fields *fields);

static void decode_adv_data(const uint8_t *adv_data, uint8_t adv_data_len, void *arg);

void print_mbuf(const struct os_mbuf *om);

/*** l2cap ***/

static int l2cap_conn_find_idx(uint16_t handle);

static struct l2cap_conn *l2cap_conn_find(uint16_t handle);

static struct l2cap_conn *l2cap_conn_add(struct ble_gap_conn_desc *desc);

static void l2cap_conn_delete_idx(int idx);

/*** l2cap coc ***/

static int l2cap_coc_add(uint16_t conn_handle, struct ble_l2cap_chan *chan);

static void l2cap_coc_remove(uint16_t conn_handle, struct ble_l2cap_chan *chan);

static void l2cap_coc_recv(struct ble_l2cap_chan *chan, struct os_mbuf *sdu);

static int l2cap_coc_accept(uint16_t conn_handle, uint16_t peer_mtu, struct ble_l2cap_chan *chan);

static void l2cap_coc_unstalled(uint16_t conn_handle, struct ble_l2cap_chan *chan);

int l2cap_create_srv(uint16_t psm, uint16_t mtu, int accept_response);

int l2cap_connect(uint16_t conn_handle, uint16_t psm, uint16_t mtu, uint8_t num);

int l2cap_disconnect(uint16_t conn_handle, uint16_t idx);

int l2cap_reconfig(uint16_t conn_handle, uint16_t mtu, uint8_t num, uint8_t idxs[]);

int l2cap_send(uint16_t conn_handle, uint16_t idx, uint16_t bytes);

int on_gap_event(struct ble_gap_event *event, void *arg);

static int on_l2cap_event(struct ble_l2cap_event *event, void *arg);

/*** nimble ***/

static void on_host_contr_reset(int reason);

static void on_host_contr_sync();

