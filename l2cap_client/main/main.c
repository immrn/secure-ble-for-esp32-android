#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_err.h"
#include "esp_spiffs.h"

#include "nvs_flash.h"

#include "esp_nimble_hci.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"

#include "app_gap.h"
#include "app_misc.h"
#include "app_l2cap.h"
#include "ssl_ctx.h"
#include "app_ssl.h"
#include "app_config.h"
#include "app_tags.h"



// Address of Bluetooth peer device
static ble_addr_t peer_bt_addr = {
    .type = BLE_OWN_ADDR_PUBLIC,
    .val = { 0xc6, 0x14, 0x62, 0xc4, 0x0a, 0x24 }
};

// Parameters for GAP discovering
static struct ble_gap_disc_params disc_params;



int on_gap_event(struct ble_gap_event *event, void *arg){
    struct ble_gap_conn_desc desc;
    int conn_idx;
    int res;

    switch (event->type){
        case BLE_GAP_EVENT_CONNECT:{
            printf("connection %s; status=%d ",
                event->connect.status == 0 ? "established" : "failed",
                event->connect.status);

            // add the L2CAP connection
            if(event->connect.status == 0){
                res = ble_gap_conn_find(event->connect.conn_handle, &desc);
                assert(res == 0);
                print_conn_desc(&desc);
                l2cap_conn_add(&desc);
                l2cap_connect(desc.conn_handle, APP_CID, L2CAP_COC_MTU, 1);
            }
            return 0;
        }
        case BLE_GAP_EVENT_DISCONNECT:{
            printf("disconnect; reason=%d ", event->disconnect.reason);
            print_conn_desc(&event->disconnect.conn);

            // remove the L2CAP connection
            conn_idx = l2cap_conn_find_idx(event->disconnect.conn.conn_handle);
            if(conn_idx != -1){
                l2cap_conn_delete_idx(conn_idx);
            }

            // restart discovering
            res = ble_gap_disc_cancel();
            assert(res == 0 || res == BLE_HS_EALREADY);
            return ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, on_gap_event, NULL);
        }
        case BLE_GAP_EVENT_DISC:{
            printf("received advertisement; event_type=%d rssi=%d addr_type=%d addr=",
                event->disc.event_type,
                event->disc.rssi,
                event->disc.addr.type);
            print_addr(event->disc.addr.val);

            // There is no adv data to print in case of connectable directed advertising
            if (event->disc.event_type == BLE_HCI_ADV_RPT_EVTYPE_DIR_IND) {
                printf("\nConnectable directed advertising event\n");
                return 0;
            }
            decode_adv_data(event->disc.data, event->disc.length_data, arg);
            
            // When target peer device was discovered, connect
            bool is_peer_disc = true;
            for(int i = 0; i < 6; i++){
                if(event->disc.addr.val[i] != peer_bt_addr.val[i]){
                    is_peer_disc = false;
                    break;
                }
            }
            if(is_peer_disc){
                res = ble_gap_disc_cancel();
                assert(res == 0 || res == BLE_HS_EALREADY);
                res = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer_bt_addr, 500, NULL, on_gap_event, NULL);
                assert(res == 0);
            }
            return 0;
        }
        case BLE_GAP_EVENT_CONN_UPDATE:{
            printf("connection updated; status=%d ", event->conn_update.status);
            res = ble_gap_conn_find(event->conn_update.conn_handle, &desc);
            assert(res == 0);
            print_conn_desc(&desc);
            return 0;
        }
        case BLE_GAP_EVENT_CONN_UPDATE_REQ:{
            printf("connection update request\n");
            *event->conn_update_req.self_params = *event->conn_update_req.peer_params;
            return 0;
        }
        case BLE_GAP_EVENT_PASSKEY_ACTION:{
            printf("passkey action event; action=%d",
                        event->passkey.params.action);
            if(event->passkey.params.action == BLE_SM_IOACT_NUMCMP){
                printf(" numcmp=%lu",
                            (unsigned long)event->passkey.params.numcmp);
            }
            printf("\n");
            return 0;
        }
        case BLE_GAP_EVENT_DISC_COMPLETE:{
            printf("discovery complete; reason=%d\n", event->disc_complete.reason);
            return 0;
        }
        case BLE_GAP_EVENT_ADV_COMPLETE:{
            printf("advertise complete; reason=%d\n", event->adv_complete.reason);
            return 0;
        }
        case BLE_GAP_EVENT_ENC_CHANGE:{
            printf("encryption change event; status=%d ", event->enc_change.status);
            res = ble_gap_conn_find(event->enc_change.conn_handle, &desc);
            assert(res == 0);
            print_conn_desc(&desc);
            return 0;
        }
        case BLE_GAP_EVENT_NOTIFY_RX:{
            printf("notification rx event; attr_handle=%d indication=%d len=%d data=",
                event->notify_rx.attr_handle,
                event->notify_rx.indication,
                OS_MBUF_PKTLEN(event->notify_rx.om));
            print_mbuf(event->notify_rx.om);
            printf("\n");
            return 0;
        }
        case BLE_GAP_EVENT_NOTIFY_TX:{
            printf("notification tx event; status=%d attr_handle=%d indication=%d\n",
                event->notify_tx.status,
                event->notify_tx.attr_handle,
                event->notify_tx.indication);
            return 0;
        }
        case BLE_GAP_EVENT_SUBSCRIBE:{
            printf("subscribe event; conn_handle=%d attr_handle=%d reason=%d prevn=%d curn=%d previ=%d curi=%d\n",
                event->subscribe.conn_handle,
                event->subscribe.attr_handle,
                event->subscribe.reason,
                event->subscribe.prev_notify,
                event->subscribe.cur_notify,
                event->subscribe.prev_indicate,
                event->subscribe.cur_indicate);
            return 0;
        }
        case BLE_GAP_EVENT_MTU:{
            printf("mtu update event; conn_handle=%d cid=%d mtu=%d\n",
                event->mtu.conn_handle,
                event->mtu.channel_id,
                event->mtu.value);
            return 0;
        }
        case BLE_GAP_EVENT_IDENTITY_RESOLVED:{
            printf("identity resolved ");
            res = ble_gap_conn_find(event->identity_resolved.conn_handle, &desc);
            assert(res == 0);
            print_conn_desc(&desc);
            return 0;
        }
        case BLE_GAP_EVENT_PHY_UPDATE_COMPLETE:{
            printf("PHY update complete; status=%d, conn_handle=%d tx_phy=%d, rx_phy=%d\n",
                event->phy_updated.status,
                event->phy_updated.conn_handle,
                event->phy_updated.tx_phy,
                event->phy_updated.rx_phy);
            return 0;
        }
        case BLE_GAP_EVENT_REPEAT_PAIRING:{
            /* We already have a bond with the peer, but it is attempting to
            * establish a new secure link.  This app sacrifices security for
            * convenience: just throw away the old bond and accept the new link.
            */

            /* Delete the old bond. */
            res = ble_gap_conn_find(event->repeat_pairing.conn_handle, &desc);
            assert(res == 0);
            ble_store_util_delete_peer(&desc.peer_id_addr);

            /* Return BLE_GAP_REPEAT_PAIRING_RETRY to indicate that the host should
            * continue with the pairing operation.
            */
            return BLE_GAP_REPEAT_PAIRING_RETRY;
        }
        default:
            return 0;
    }
}

int on_l2cap_event(struct ble_l2cap_event *event, void *arg){
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
            // Client doesn't accept connections
        }
        case BLE_L2CAP_EVENT_COC_DATA_RECEIVED:{
            l2cap_coc_recv(event->receive.conn_handle ,event->receive.chan, event->receive.sdu_rx);
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

// NimBLE

void on_host_contr_reset(int reason){
    MODLOG_DFLT(ERROR, "Reseted host and controller; reason=%d\n", reason);
}

void on_host_contr_sync(){
    //Maybe there are some things TODO here

    MODLOG_DFLT(INFO, "synchronised host and controller\n");
}

void host_task_func(void *param)
{
    ESP_LOGI("NIMBLE", "BLE Host Task Started");
    // This function will return only when nimble_port_stop() is executed
    nimble_port_run();

    nimble_port_freertos_deinit();
}

// Heap

static void failed_alloc_cb(size_t size, uint32_t caps, const char* func_name){
    ESP_LOGE(HEAP_TAG, "Failed to allocate %zu bytes in %s", size, func_name);
    return;
}



void app_main(void){
    int ret;

    // Heap
    ret = heap_caps_register_failed_alloc_callback(failed_alloc_cb);
    if(ret){
        ESP_LOGE(HEAP_TAG, "heap_caps_register_failed_alloc_callback() failed (%s)", esp_err_to_name(ret));
    }
    // Check heap
    ESP_LOGI(HEAP_TAG, "Free bytes in (data memory) heap:\t\t%zu", heap_caps_get_free_size(MALLOC_CAP_8BIT));
    ESP_LOGI(HEAP_TAG, "Largest free block in (data memory) heap:\t%zu", heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));

    // Setup and mount SPIFFS
    ESP_LOGI(SPIFFS_TAG, "Initializing SPIFFS");

    esp_vfs_spiffs_conf_t conf = {
      .base_path = "/spiffs",
      .partition_label = NULL,
      .max_files = 5,
      .format_if_mount_failed = false
    };

    ret = esp_vfs_spiffs_register(&conf);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(SPIFFS_TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(SPIFFS_TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(SPIFFS_TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(SPIFFS_TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
    } else {
        ESP_LOGI(SPIFFS_TAG, "Partition size: total: %d, used: %d", total, used);
    }

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

    // Initialize L2CAP RX memory pool
    ret = os_mempool_init(&sdu_coc_mbuf_mempool_rx, L2CAP_COC_BUF_COUNT_RX, L2CAP_COC_MEM_BLOCK_SIZE, l2cap_sdu_coc_mem_rx, "l2cap_coc_sdu_rx_pool");
    assert(ret == 0);
    ret = os_mbuf_pool_init(&sdu_os_mbuf_pool_rx, &sdu_coc_mbuf_mempool_rx, L2CAP_COC_MEM_BLOCK_SIZE, L2CAP_COC_BUF_COUNT_RX);
    assert(ret == 0);
    // Initialize RX SDU queue to track the order of the SDUs/mbufs in the sdu_os_mbuf_pool_rx. Length = L2CAP_COC_BUF_COUNT_RX - 1, because one RX-Buffer must always be available to ble_l2cap_recv_ready() and can't be tracked.
    sdu_queue_init(&sdu_queue_rx, L2CAP_COC_BUF_COUNT_RX - 1);

    // Initialize L2CAP TX memory pool
    ret = os_mempool_init(&sdu_coc_mbuf_mempool_tx, L2CAP_COC_BUF_COUNT_TX, L2CAP_COC_MEM_BLOCK_SIZE, l2cap_sdu_coc_mem_tx, "l2cap_coc_sdu_tx_pool");
    assert(ret == 0);
    ret = os_mbuf_pool_init(&sdu_os_mbuf_pool_tx, &sdu_coc_mbuf_mempool_tx, L2CAP_COC_MEM_BLOCK_SIZE, L2CAP_COC_BUF_COUNT_TX);
    assert(ret == 0);

    // Initialize L2CAP connection memory pool
    ret = os_mempool_init(&l2cap_coc_conn_pool, MYNEWT_VAL(BLE_L2CAP_COC_MAX_NUM), sizeof (struct l2cap_coc_node), l2cap_coc_conn_mem, "l2cap_coc_conn_pool");
    assert(ret == 0);

    // Initialize the NimBLE host configuration
    ble_hs_cfg.reset_cb = on_host_contr_reset;
    ble_hs_cfg.sync_cb = on_host_contr_sync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;
    ble_hs_cfg.sm_sc = 0;
    nimble_port_freertos_init(host_task_func);

    printf("mempool free blocks: rx = %d, tx = %d\n", sdu_coc_mbuf_mempool_rx.mp_num_free, sdu_coc_mbuf_mempool_tx.mp_num_free);

    // Create SSL context
    io_ctx io;
    ssl_ctx ctx;
    // Using ssl_ctx_create but as a client!
	ssl_ctx_create(&ctx, MBEDTLS_SSL_IS_CLIENT, "/spiffs/crypto/app_clt.key", "/spiffs/crypto/app_clt.crt", "/spiffs/crypto/ca.crt", "fb_steigtum_bike_srv", send_data, recv_data, &io);

    // Setup discovering
    memset(&disc_params, 0, sizeof(disc_params));
    disc_params.itvl = BLE_GAP_SCAN_FAST_INTERVAL_MAX;
    disc_params.window = BLE_GAP_SCAN_FAST_WINDOW;
    disc_params.filter_duplicates = 1;
    // Wait for host and controller getting synchronized
    while(!ble_hs_synced()){
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
    // Start discovering
    ret = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &disc_params, on_gap_event, NULL);
    assert(ret == 0);

    test_mbedtls_1(&io, &ctx);

    return;
}
