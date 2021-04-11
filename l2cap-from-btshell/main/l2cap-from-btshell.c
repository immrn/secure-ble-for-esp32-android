#include <stdio.h>
#include <errno.h>

#include "nvs_flash.h"

#include "os/os_mbuf.h"
#include "os/os_mempool.h"
#include "esp_nimble_hci.h"
#include "host/ble_hs.h"
#include "../src/ble_hs_priv.h"
#include "host/ble_l2cap.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "host/ble_store.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "l2cap-from-btshell.h"

#define CONFIG_BT_NIMBLE_DEBUG

#define APP_CID 0xffff
#define L2CAP_COC_MTU 256
#define L2CAP_COC_BUF_COUNT (3 * MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM))

#define INT_TO_PTR(x)     (void *)((intptr_t)(x))
#define PTR_TO_INT(x)     (int) ((intptr_t)(x))

/*** gap ***/

static struct{
    bool restart;
    uint8_t own_addr_type;
    ble_addr_t direct_addr;
    int32_t duration_ms;
    struct ble_gap_adv_params params;
} adv_params;

struct scan_opts{
    uint16_t limit;
    uint8_t ignore_legacy:1;
    uint8_t periodic_only:1;
};

/*** l2cap ***/

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

static os_membuf_t l2cap_coc_conn_mem[OS_MEMPOOL_SIZE(MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM), sizeof(struct l2cap_coc_struct))];
static struct os_mempool l2cap_coc_conn_pool;

static os_membuf_t l2cap_sdu_coc_mem[OS_MEMPOOL_SIZE(L2CAP_COC_BUF_COUNT, L2CAP_COC_MTU)];
struct os_mbuf_pool sdu_os_mbuf_pool;
static struct os_mempool sdu_coc_mbuf_mempool;

/*** gap ***/

int adv_start(uint8_t own_addr_type, const ble_addr_t *direct_addr, int32_t duration_ms, const struct ble_gap_adv_params *params, bool restart){
    if(restart){
        adv_params.restart = restart;
        adv_params.own_addr_type = own_addr_type;
        adv_params.duration_ms = duration_ms;

        if(direct_addr){
            memcpy(&adv_params.direct_addr, direct_addr, sizeof(adv_params.direct_addr));
        }

        if(params){
            memcpy(&adv_params.params, params, sizeof(adv_params.params));
        }
    }

    int rc = ble_gap_adv_start(own_addr_type, direct_addr, duration_ms, params, on_gap_event, NULL);
    return rc;
}

int adv_stop(void){
    adv_params.restart = false;

    int rc = ble_gap_adv_stop();
    return rc;
}

static int adv_restart(struct ble_gap_event *event){
    if (event->type != BLE_GAP_EVENT_DISCONNECT) {
        return -1;
    }

    if (!adv_params.restart) {
        return 0;
    }

    int rc = ble_gap_adv_start(adv_params.own_addr_type, &adv_params.direct_addr, adv_params.duration_ms, &adv_params.params, on_gap_event, NULL);
    return rc;
}

void print_addr(const void *addr){
    const uint8_t *u8p;

    u8p = addr;
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        u8p[5], u8p[4], u8p[3], u8p[2], u8p[1], u8p[0]);
}

void print_conn_desc(const struct ble_gap_conn_desc *desc){
    printf("handle=%d our_ota_addr_type=%d our_ota_addr=",
        desc->conn_handle, desc->our_ota_addr.type);
    print_addr(desc->our_ota_addr.val);
    printf(" our_id_addr_type=%d our_id_addr=",
        desc->our_id_addr.type);
    print_addr(desc->our_id_addr.val);
    printf(" peer_ota_addr_type=%d peer_ota_addr=",
        desc->peer_ota_addr.type);
    print_addr(desc->peer_ota_addr.val);
    printf(" peer_id_addr_type=%d peer_id_addr=",
        desc->peer_id_addr.type);
    print_addr(desc->peer_id_addr.val);
    printf(" conn_itvl=%d conn_latency=%d supervision_timeout=%d key_size=%d encrypted=%d authenticated=%d bonded=%d\n",
        desc->conn_itvl, desc->conn_latency,
        desc->supervision_timeout,
        desc->sec_state.key_size,
        desc->sec_state.encrypted,
        desc->sec_state.authenticated,
        desc->sec_state.bonded);
}

void print_bytes(const uint8_t *bytes, int len){
    for(int i = 0; i < len; i++){
        printf("%s0x%02x", i != 0 ? ":" : "", bytes[i]);
    }
}

static void print_adv_fields(const struct ble_hs_adv_fields *fields){
    const uint8_t *u8p;
    int i;

    if(fields->flags != 0){
        printf("    flags=0x%02x:\n", fields->flags);

        if(!(fields->flags & BLE_HS_ADV_F_DISC_LTD) && !(fields->flags & BLE_HS_ADV_F_DISC_GEN)){
            printf("        Non-discoverable mode\n");
        }

        if(fields->flags & BLE_HS_ADV_F_DISC_LTD){
            printf("        Limited discoverable mode\n");
        }

        if(fields->flags & BLE_HS_ADV_F_DISC_GEN){
            printf("        General discoverable mode\n");
        }

        if(fields->flags & BLE_HS_ADV_F_BREDR_UNSUP){
            printf("        BR/EDR not supported\n");
        }
    }

    // if(fields->uuids16 != NULL){
    //     printf("    uuids16(%scomplete)=", fields->uuids16_is_complete ? "" : "in");
    //     for(i = 0; i < fields->num_uuids16; i++){
    //         print_uuid(&fields->uuids16[i].u);
    //         printf(" ");
    //     }
    //     printf("\n");
    // }

    // if(fields->uuids32 != NULL){
    //     printf("    uuids32(%scomplete)=", fields->uuids32_is_complete ? "" : "in");
    //     for(i = 0; i < fields->num_uuids32; i++){
    //         print_uuid(&fields->uuids32[i].u);
    //         printf(" ");
    //     }
    //     printf("\n");
    // }

    // if(fields->uuids128 != NULL){
    //     printf("    uuids128(%scomplete)=", fields->uuids128_is_complete ? "" : "in");
    //     for(i = 0; i < fields->num_uuids128; i++){
    //         print_uuid(&fields->uuids128[i].u);
    //         printf(" ");
    //     }
    //     printf("\n");
    // }

    // if(fields->name != NULL){
    //     printf("    name(%scomplete)=", fields->name_is_complete ? "" : "in");
    //     console_write((char *)fields->name, fields->name_len);
    //     printf("\n");
    // }

    if(fields->tx_pwr_lvl_is_present){
        printf("    tx_pwr_lvl=%d\n", fields->tx_pwr_lvl);
    }

    if(fields->slave_itvl_range != NULL){
        printf("    slave_itvl_range=");
        print_bytes(fields->slave_itvl_range, BLE_HS_ADV_SLAVE_ITVL_RANGE_LEN);
        printf("\n");
    }

    if(fields->svc_data_uuid16 != NULL){
        printf("    svc_data_uuid16=");
        print_bytes(fields->svc_data_uuid16, fields->svc_data_uuid16_len);
        printf("\n");
    }

    if(fields->public_tgt_addr != NULL){
        printf("    public_tgt_addr=");
        u8p = fields->public_tgt_addr;
        for(i = 0; i < fields->num_public_tgt_addrs; i++){
            print_addr(u8p);
            u8p += BLE_HS_ADV_PUBLIC_TGT_ADDR_ENTRY_LEN;
        }
        printf("\n");
    }

    if(fields->appearance_is_present){
        printf("    appearance=0x%04x\n", fields->appearance);
    }

    if(fields->adv_itvl_is_present){
        printf("    adv_itvl=0x%04x\n", fields->adv_itvl);
    }

    if(fields->svc_data_uuid32 != NULL){
        printf("    svc_data_uuid32=");
        print_bytes(fields->svc_data_uuid32, fields->svc_data_uuid32_len);
        printf("\n");
    }

    if(fields->svc_data_uuid128 != NULL){
        printf("    svc_data_uuid128=");
        print_bytes(fields->svc_data_uuid128, fields->svc_data_uuid128_len);
        printf("\n");
    }

    if(fields->uri != NULL){
        printf("    uri=");
        print_bytes(fields->uri, fields->uri_len);
        printf("\n");
    }

    if(fields->mfg_data != NULL){
        printf("    mfg_data=");
        print_bytes(fields->mfg_data, fields->mfg_data_len);
        printf("\n");
    }
}

static void decode_adv_data(const uint8_t *adv_data, uint8_t adv_data_len, void *arg){
    struct scan_opts *scan_opts = arg;
    struct ble_hs_adv_fields fields;

    printf(" data_length=%d data=", adv_data_len);

    if(scan_opts){
        adv_data_len = min(adv_data_len, scan_opts->limit);
    }

    print_bytes(adv_data, adv_data_len);

    printf(" fields:\n");
    ble_hs_adv_parse_fields(&fields, adv_data, adv_data_len);
    print_adv_fields(&fields);
}

void print_mbuf(const struct os_mbuf *om){
    int colon = 0;
    while(om != NULL){
        if(colon){
            printf(":");
        }else{
            colon = 1;
        }
        print_bytes(om->om_data, om->om_len);
        om = SLIST_NEXT(om, om_next);
    }
}

/*** l2cap ***/

static int l2cap_conn_find_idx(uint16_t handle){
    for(int i = 0; i < l2cap_conns_num; i++){
        if(l2cap_conns[i].handle == handle){
            return i;
        }
    }
    return -1;
}

static struct l2cap_conn *l2cap_conn_find(uint16_t handle){
    int idx = l2cap_conn_find_idx(handle);
    if(idx == -1){
        return NULL;
    }else{
        return l2cap_conns + idx;
    }
}

static struct l2cap_conn *l2cap_conn_add(struct ble_gap_conn_desc *desc){
    struct l2cap_conn *conn;

    assert(l2cap_conns_num < MYNEWT_VAL(BLE_MAX_CONNECTIONS));

    conn = l2cap_conns + l2cap_conns_num;
    l2cap_conns_num++;

    conn->handle = desc->conn_handle;
    SLIST_INIT(&conn->coc_list);

    return conn;
}

static void l2cap_conn_delete_idx(int idx){
    assert(idx >= 0 && idx < l2cap_conns_num);

    for(int i = idx + 1; i < l2cap_conns_num; i++){
        l2cap_conns[i - 1] = l2cap_conns[i];
    }

    l2cap_conns_num--;
}

/*** l2cap coc ***/

static int l2cap_coc_add(uint16_t conn_handle, struct ble_l2cap_chan *chan){
    struct l2cap_conn *conn;
    struct l2cap_coc_struct *coc;
    struct l2cap_coc_struct *prev, *cur;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = os_memblock_get(&l2cap_coc_conn_pool);
    if(!coc){
        return ENOMEM;
    }

    coc->chan = chan;

    prev = NULL;
    SLIST_FOREACH(cur, &conn->coc_list, next){
        prev = cur;
    }

    if(prev == NULL){
        SLIST_INSERT_HEAD(&conn->coc_list, coc, next);
    }else{
        SLIST_INSERT_AFTER(prev, coc, next);
    }

    return 0;
}

static void l2cap_coc_remove(uint16_t conn_handle, struct ble_l2cap_chan *chan){
    struct l2cap_conn *conn;
    struct l2cap_coc_struct *coc;
    struct l2cap_coc_struct *cur;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = NULL;
    SLIST_FOREACH(cur, &conn->coc_list, next){
        if(cur->chan == chan){
            coc = cur;
            break;
        }
    }

    if(!coc){
        return;
    }

    SLIST_REMOVE(&conn->coc_list, coc, l2cap_coc_struct, next);
    os_memblock_put(&l2cap_coc_conn_pool, coc);
}

static void l2cap_coc_recv(struct ble_l2cap_chan *chan, struct os_mbuf *sdu){
    printf("LE CoC SDU received, chan: 0x%08x, data len %d\n", (uint32_t) chan, OS_MBUF_PKTLEN(sdu));

    os_mbuf_free_chain(sdu);
    sdu = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool, 0);
    assert(sdu != NULL);

    if(ble_l2cap_recv_ready(chan, sdu) != 0){
        assert(0);
    }
}

static int l2cap_coc_accept(uint16_t conn_handle, uint16_t peer_mtu, struct ble_l2cap_chan *chan){
    struct os_mbuf *sdu_rx;

    printf("LE CoC accepting, chan: 0x%08x, peer_mtu %d\n", (uint32_t) chan, peer_mtu);

    sdu_rx = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool, 0);
    if(!sdu_rx){
        return BLE_HS_ENOMEM;
    }

    return ble_l2cap_recv_ready(chan, sdu_rx);
}

static void l2cap_coc_unstalled(uint16_t conn_handle, struct ble_l2cap_chan *chan){
    struct l2cap_conn *conn;
    struct l2cap_coc_struct *coc;
    struct l2cap_coc_struct *cur;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = NULL;
    SLIST_FOREACH(cur, &conn->coc_list, next) {
        if(cur->chan == chan){
            coc = cur;
            break;
        }
    }

    if(!coc){
        return;
    }

    coc->stalled = false;
}

int l2cap_create_srv(uint16_t psm, uint16_t mtu, int accept_response){
    if(mtu == 0 || mtu > L2CAP_COC_MTU){
        mtu = L2CAP_COC_MTU;
    }

    return ble_l2cap_create_server(psm, mtu, on_l2cap_event,
                                   INT_TO_PTR(accept_response));
}

int l2cap_connect(uint16_t conn_handle, uint16_t psm, uint16_t mtu, uint8_t num){
    struct os_mbuf *sdu_rx[num];
    int i;

    if(mtu == 0 || mtu > L2CAP_COC_MTU){
        mtu = L2CAP_COC_MTU;
    }

    printf("L2CAP CoC MTU: %d, max available %d\n", mtu, L2CAP_COC_MTU);

    for(i = 0; i < num; i++){
        sdu_rx[i] = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool, 0);
        assert(sdu_rx != NULL);
    }

    if(num == 1){
        return ble_l2cap_connect(conn_handle, psm, mtu, sdu_rx[0], on_l2cap_event, NULL);
    }

    return ble_l2cap_enhanced_connect(conn_handle, psm, mtu, num, sdu_rx,on_l2cap_event, NULL);
}

int l2cap_disconnect(uint16_t conn_handle, uint16_t idx){
    struct l2cap_conn *conn;
    struct l2cap_coc_struct *coc;
    int i;
    int rc = 0;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    i = 0;
    SLIST_FOREACH(coc, &conn->coc_list, next){
        if(i == idx){
                break;
        }
        i++;
    }
    assert(coc != NULL);

    rc = ble_l2cap_disconnect(coc->chan);
    if(rc){
        printf("Could not disconnect channel rc=%d\n", rc);
    }

    return rc;
}

int l2cap_reconfig(uint16_t conn_handle, uint16_t mtu, uint8_t num, uint8_t idxs[]){
    struct l2cap_conn *conn;
    struct l2cap_coc_struct *coc;
    struct ble_l2cap_chan * chans[5] = {0};
    int i, j;
    int cnt;

    conn = l2cap_conn_find(conn_handle);
    if(conn == NULL){
        printf("conn=%d does not exist\n", conn_handle);
        return 0;
    }

    i = 0;
    j = 0;
    cnt = 0;
    SLIST_FOREACH(coc, &conn->coc_list, next){
        for(i = 0; i < num; i++){
            if(idxs[i] == j){
                chans[cnt] = coc->chan;
                cnt++;
                break;
            }
        }
        j++;
    }

    if(cnt != num){
        printf("Missing coc? (%d!=%d)\n", num, cnt);
        return BLE_HS_EINVAL;
    }

    return ble_l2cap_reconfig(chans, cnt, mtu);
}

int l2cap_send(uint16_t conn_handle, uint16_t idx, uint16_t bytes){
    struct l2cap_conn *conn;
    struct l2cap_coc_struct *coc;
    struct os_mbuf *sdu_tx;
    uint8_t b[] = {0x00, 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88, 0x99};
    int i;
    int rc;

    printf("conn=%d, idx=%d, bytes=%d\n", conn_handle, idx, bytes);

    conn = l2cap_conn_find(conn_handle);
    if(conn == NULL){
        printf("conn=%d does not exist\n", conn_handle);
        return 0;
    }

    i = 0;
    SLIST_FOREACH(coc, &conn->coc_list, next){
        if(i == idx){
            break;
        }
        i++;
    }
    if(coc == NULL){
        printf("Are you sure your channel exist?\n");
        return 0;
    }

    if(coc->stalled){
        printf("Channel is stalled, wait ...\n");
        return 0;
    }

    sdu_tx = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool, 0);
    if (sdu_tx == NULL) {
        printf("No memory in the test sdu pool\n");
        return 0;
    }

    /* For the testing purpose we fill up buffer with known data, easy
     * to validate on other side. In this loop we add as many full chunks as we
     * can
     */
    for(i = 0; i < bytes / sizeof(b); i++){
        rc = os_mbuf_append(sdu_tx, b, sizeof(b));
        if(rc){
            printf("Cannot append data %i !\n", i);
            os_mbuf_free_chain(sdu_tx);
            return rc;
        }
    }

    /* Here we add the rest < sizeof(b) */
    rc = os_mbuf_append(sdu_tx, b, bytes - (sizeof(b) * i));
    if(rc){
        printf("Cannot append data %i !\n", i);
        os_mbuf_free_chain(sdu_tx);
        return rc;
    }

    rc = ble_l2cap_send(coc->chan, sdu_tx);
    if(rc){
        if(rc == BLE_HS_ESTALLED){
          printf("CoC module is stalled with data. Wait for unstalled \n");
          coc->stalled = true;
        }else{
            printf("Could not send data rc=%d\n", rc);
        }
        os_mbuf_free_chain(sdu_tx);
    }

    return rc;
}

/*** event handling ***/

int on_gap_event(struct ble_gap_event *event, void *arg){
    struct ble_gap_conn_desc desc;
    int conn_idx;
    int rc;

    switch (event->type){
        case BLE_GAP_EVENT_CONNECT:
            printf("connection %s; status=%d ",
                event->connect.status == 0 ? "established" : "failed",
                event->connect.status);

            if(event->connect.status == 0){
                rc = ble_gap_conn_find(event->connect.conn_handle, &desc);
                assert(rc == 0);
                print_conn_desc(&desc);
                l2cap_conn_add(&desc);
            }
            return 0;

        case BLE_GAP_EVENT_DISCONNECT:
            printf("disconnect; reason=%d ", event->disconnect.reason);
            print_conn_desc(&event->disconnect.conn);

            conn_idx = l2cap_conn_find_idx(event->disconnect.conn.conn_handle);
            if(conn_idx != -1){
                l2cap_conn_delete_idx(conn_idx);
            }
            return adv_restart(event);

        case BLE_GAP_EVENT_DISC:
            printf("received advertisement; event_type=%d rssi=%d addr_type=%d addr=",
                event->disc.event_type,
                event->disc.rssi,
                event->disc.addr.type);
            print_addr(event->disc.addr.val);

            /*
            * There is no adv data to print in case of connectable
            * directed advertising
            */
            if (event->disc.event_type == BLE_HCI_ADV_RPT_EVTYPE_DIR_IND) {
                printf("\nConnectable directed advertising event\n");
                return 0;
            }
            decode_adv_data(event->disc.data, event->disc.length_data, arg);
            return 0;

        case BLE_GAP_EVENT_CONN_UPDATE:
            printf("connection updated; status=%d ", event->conn_update.status);
            rc = ble_gap_conn_find(event->conn_update.conn_handle, &desc);
            assert(rc == 0);
            print_conn_desc(&desc);
            return 0;

        case BLE_GAP_EVENT_CONN_UPDATE_REQ:
            printf("connection update request\n");
            *event->conn_update_req.self_params = *event->conn_update_req.peer_params;
            return 0;

        case BLE_GAP_EVENT_PASSKEY_ACTION:
            printf("passkey action event; action=%d",
                        event->passkey.params.action);
            if(event->passkey.params.action == BLE_SM_IOACT_NUMCMP){
                printf(" numcmp=%lu",
                            (unsigned long)event->passkey.params.numcmp);
            }
            printf("\n");
            return 0;

        case BLE_GAP_EVENT_DISC_COMPLETE:
            printf("discovery complete; reason=%d\n", event->disc_complete.reason);
            return 0;

        case BLE_GAP_EVENT_ADV_COMPLETE:
            printf("advertise complete; reason=%d\n", event->adv_complete.reason);
            return 0;

        case BLE_GAP_EVENT_ENC_CHANGE:
            printf("encryption change event; status=%d ", event->enc_change.status);
            rc = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
            assert(rc == 0);
            print_conn_desc(&desc);
            return 0;

        case BLE_GAP_EVENT_NOTIFY_RX:
            printf("notification rx event; attr_handle=%d indication=%d len=%d data=",
                event->notify_rx.attr_handle,
                event->notify_rx.indication,
                OS_MBUF_PKTLEN(event->notify_rx.om));
            print_mbuf(event->notify_rx.om);
            printf("\n");
            return 0;

        case BLE_GAP_EVENT_NOTIFY_TX:
            printf("notification tx event; status=%d attr_handle=%d indication=%d\n",
                event->notify_tx.status,
                event->notify_tx.attr_handle,
                event->notify_tx.indication);
            return 0;

        case BLE_GAP_EVENT_SUBSCRIBE:
            printf("subscribe event; conn_handle=%d attr_handle=%d reason=%d prevn=%d curn=%d previ=%d curi=%d\n",
                event->subscribe.conn_handle,
                event->subscribe.attr_handle,
                event->subscribe.reason,
                event->subscribe.prev_notify,
                event->subscribe.cur_notify,
                event->subscribe.prev_indicate,
                event->subscribe.cur_indicate);
            return 0;

        case BLE_GAP_EVENT_MTU:
            printf("mtu update event; conn_handle=%d cid=%d mtu=%d\n",
                event->mtu.conn_handle,
                event->mtu.channel_id,
                event->mtu.value);
            return 0;

        case BLE_GAP_EVENT_IDENTITY_RESOLVED:
            printf("identity resolved ");
            rc = ble_gap_conn_find(event->identity_resolved.conn_handle, &desc);
            assert(rc == 0);
            print_conn_desc(&desc);
            return 0;

        case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:
            printf("PHY update complete; status=%d, conn_handle=%d tx_phy=%d, rx_phy=%d\n",
                event->phy_updated.status,
                event->phy_updated.conn_handle,
                event->phy_updated.tx_phy,
                event->phy_updated.rx_phy);
            return 0;

        case BLE_GAP_EVENT_REPEAT_PAIRING:
            /* We already have a bond with the peer, but it is attempting to
            * establish a new secure link.  This app sacrifices security for
            * convenience: just throw away the old bond and accept the new link.
            */

            /* Delete the old bond. */
            rc = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
            assert(rc == 0);
            ble_store_util_delete_peer(&desc.peer_id_addr);

            /* Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
            * continue with the pairing operation.
            */
            return BLE_GAP_REPEAT_PAIRING_RETRY;

        default:
            return 0;
    }
}

static int on_l2cap_event(struct ble_l2cap_event *event, void *arg){
    int accept_response;
    struct ble_l2cap_chan_info chan_info;

    switch(event->type){
        case BLE_L2CAP_EVENT_COC_CONNECTED:{
            if(event->connect.status){
                printf("LE COC error: %d\n", event->connect.status);
                return 0;
            }

            if(ble_l2cap_get_chan_info(event->connect.chan, &chan_info)){
                assert(0);
            }

            printf("LE COC connected, conn: %d, chan: %p, psm: 0x%02x, scid: 0x%04x, dcid: 0x%04x, our_mps: %d, our_mtu: %d, peer_mps: %d, peer_mtu: %d\n",
                event->connect.conn_handle, event->connect.chan, chan_info.psm, chan_info.scid, chan_info.dcid,
                chan_info.our_l2cap_mtu, chan_info.our_coc_mtu, chan_info.peer_l2cap_mtu, chan_info.peer_coc_mtu);

            l2cap_coc_add(event->connect.conn_handle, event->connect.chan);

            return 0;
        }
        case BLE_L2CAP_EVENT_COC_DISCONNECTED:{
            printf("LE CoC disconnected, chan: %p\n", event->disconnect.chan);

            l2cap_coc_remove(event->disconnect.conn_handle, event->disconnect.chan);
            return 0;
        }
        case BLE_L2CAP_EVENT_COC_ACCEPT:{
            accept_response = PTR_TO_INT(arg);
            if (accept_response) {
                return accept_response;
            }

            return l2cap_coc_accept(event->accept.conn_handle, event->accept.peer_sdu_size, event->accept.chan);
        }
        case BLE_L2CAP_EVENT_COC_DATA_RECEIVED:{
            l2cap_coc_recv(event->receive.chan, event->receive.sdu_rx);
            return 0;
        }
        case BLE_L2CAP_EVENT_COC_RECONFIG_COMPLETED:{
            if(ble_l2cap_get_chan_info(event->reconfigured.chan, &chan_info)){
                assert(0);
            }

            printf("LE CoC reconfigure completed status 0x%02x, chan: %p\n",
                event->reconfigured.status,
                event->reconfigured.chan);

            if(event->reconfigured.status == 0){
                printf("\t our_mps: %d our_mtu %d\n", chan_info.our_l2cap_mtu, chan_info.our_coc_mtu);
            }
            return 0;
        }
        case BLE_L2CAP_EVENT_COC_PEER_RECONFIGURED:{
            if(ble_l2cap_get_chan_info(event->reconfigured.chan, &chan_info)){
                assert(0);
            }

            printf("LE CoC peer reconfigured status 0x%02x, chan: %p\n",
                event->reconfigured.status,
                event->reconfigured.chan);

            if(event->reconfigured.status == 0){
                printf("\t peer_mps: %d peer_mtu %d\n", chan_info.peer_l2cap_mtu, chan_info.peer_coc_mtu);
            }

            return 0;
        }
        case BLE_L2CAP_EVENT_COC_TX_UNSTALLED:{
            printf("L2CAP CoC channel %p unstalled, last sdu sent with err=0x%02x\n",
                event->tx_unstalled.chan, event->tx_unstalled.status);
            l2cap_coc_unstalled(event->tx_unstalled.conn_handle, event->tx_unstalled.chan);
            return 0;
        }
        default:{
            return 0;
        }
    }
}

/*** nimble ***/

static void on_host_contr_reset(int reason){
    MODLOG_DFLT(ERROR, "Reseted host and controller; reason=%d\n", reason);
}

static void on_host_contr_sync(){
    //Maybe there are some things TODO here

    MODLOG_DFLT(INFO, "synchronised host and controller\n");
}

// int ble_l2cap_sig_update
// ble_l2cap_create_server
// ble_l2cap_connect or ble_l2cap_enhanced_connect
// ble_l2cap_disconnect
// ble_l2cap_reconfig
// ble_l2cap_send

void host_task_func(void *param)
{
    ESP_LOGI("NIMBLE", "BLE Host Task Started");
    // This function will return only when nimble_port_stop() is executed
    nimble_port_run();

    nimble_port_freertos_deinit();
}

static struct ble_gap_adv_params params;

void app_main(void){
    int ret;

    // Initialize NVS — it is used to store PHY calibration data
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize NimBLE
    ESP_ERROR_CHECK(esp_nimble_hci_and_controller_init());
    nimble_port_init();

    // Initialize l2cap memory pools
    ret = os_mempool_init(&sdu_coc_mbuf_mempool, L2CAP_COC_BUF_COUNT, L2CAP_COC_MTU, l2cap_sdu_coc_mem, "l2cap_coc_sdu_pool");
    assert(ret == 0);
    ret = os_mbuf_pool_init(&sdu_os_mbuf_pool, &sdu_coc_mbuf_mempool, L2CAP_COC_MTU, L2CAP_COC_BUF_COUNT);
    assert(ret == 0);
    ret = os_mempool_init(&l2cap_coc_conn_pool, MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM), sizeof (struct l2cap_coc_struct), l2cap_coc_conn_mem, "l2cap_coc_conn_pool");
    assert(ret == 0);

    // Initialize the NimBLE host configuration
    ble_hs_cfg.reset_cb = on_host_contr_reset;
    ble_hs_cfg.sync_cb = on_host_contr_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    nimble_port_freertos_init(host_task_func);

    ble_l2cap_create_server(APP_CID, L2CAP_COC_MTU, on_l2cap_event, NULL);

    // Advertising
    ret = ble_svc_gap_device_name_set("nimble-device");
    assert(ret == 0);
    // ble_store_config_init();
    params.conn_mode = BLE_GAP_CONN_MODE_UND;
    params.disc_mode = BLE_GAP_DISC_MODE_GEN;
    // params.itvl_min = 0;
    // params.itvl_max = 0;
    // params.channel_map = 0;
    //ble_gap_adv_set_data
    ret = adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER, &params, false);
    assert(ret == 0);
}
