#include "app_l2cap.h"

int l2cap_conn_find_idx(uint16_t handle){
    for(int i = 0; i < l2cap_conns_num; i++){
        if(l2cap_conns[i].handle == handle){
            return i;
        }
    }
    return -1;
}

struct l2cap_conn* l2cap_conn_find(uint16_t handle){
    int conn_idx = l2cap_conn_find_idx(handle);
    if(conn_idx == -1){
        return NULL;
    }else{
        return l2cap_conns + conn_idx;
    }
}

struct l2cap_conn* l2cap_conn_add(struct ble_gap_conn_desc *desc){
    struct l2cap_conn* conn;

    assert(l2cap_conns_num < MYNEWT_VAL(BLE_MAX_CONNECTIONS));

    conn = l2cap_conns + l2cap_conns_num;
    l2cap_conns_num++;

    conn->handle = desc->conn_handle;
    SLIST_INIT(&conn->coc_list);

    return conn;
}

void l2cap_conn_delete_idx(int conn_idx){
    assert(conn_idx >= 0 && conn_idx < l2cap_conns_num);

    for(int i = conn_idx + 1; i < l2cap_conns_num; i++){
        l2cap_conns[i - 1] = l2cap_conns[i];
    }

    l2cap_conns_num--;
}

/*** l2cap coc ***/

struct l2cap_coc_node* l2cap_coc_find(struct l2cap_conn* conn, struct ble_l2cap_chan* chan){
    struct l2cap_coc_node* coc;
    struct l2cap_coc_node* cur;

    coc = NULL;
    SLIST_FOREACH(cur, &conn->coc_list, next){
        if(cur->chan == chan){
            coc = cur;
            break;
        }
    }

    return coc;
}

struct l2cap_coc_node* l2cap_coc_find_by_idx(struct l2cap_conn* conn, uint16_t coc_idx){
    struct l2cap_coc_node *coc;

    int i = 0;
    SLIST_FOREACH(coc, &conn->coc_list, next){
        if(i == coc_idx){
            break;
        }
        i++;
    }

    return coc;
}

int l2cap_coc_add(uint16_t conn_handle, struct ble_l2cap_chan *chan){
    struct l2cap_conn *conn;
    struct l2cap_coc_node *coc;
    struct l2cap_coc_node *prev, *cur;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = os_memblock_get(&l2cap_coc_conn_pool);
    if(!coc){
        return ENOMEM;
    }

    // Initialize COC node
    coc->chan = chan;
    coc->unstalled_semaphore = xSemaphoreCreateBinary();
    coc->received_data_semaphore = xSemaphoreCreateBinary();
    // NULL if allocation was unsuccessful
    assert(coc->unstalled_semaphore != NULL);
    assert(coc->received_data_semaphore != NULL);

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

void l2cap_coc_remove(uint16_t conn_handle, struct ble_l2cap_chan *chan){
    struct l2cap_conn* conn;
    struct l2cap_coc_node *coc;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = l2cap_coc_find(conn, chan);
    assert(coc != NULL);

    // Free the memory of the semaphores
    vSemaphoreDelete(coc->unstalled_semaphore);
    vSemaphoreDelete(coc->received_data_semaphore);

    SLIST_REMOVE(&conn->coc_list, coc, l2cap_coc_node, next);
    os_memblock_put(&l2cap_coc_conn_pool, coc);
}

void l2cap_coc_recv(uint16_t conn_handle, struct ble_l2cap_chan *chan, struct os_mbuf *sdu){
    int res;
    struct l2cap_conn* conn;
    struct l2cap_coc_node *coc;
    static int sdu_count = 0; // TODO DEBUG remove
    
    printf("LE CoC SDU received, #%d, chan: 0x%08x, data len %d\n", sdu_count++, (uint32_t) chan, OS_MBUF_PKTLEN(sdu));

    res = sdu_queue_add(&sdu_queue_rx, sdu);
    assert(res == 0);

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = l2cap_coc_find(conn, chan);
    assert(coc != NULL);

    // Signal the COC the arrival of data
    xSemaphoreGive(coc->received_data_semaphore);

    // os_mbuf_free_chain(sdu);

    // sdu = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool_rx, 0);
    // assert(sdu != NULL);

    // if(ble_l2cap_recv_ready(chan, sdu) != 0){
    //     assert(0);
    // }

    printf("mempool free blocks: rx = %d, tx = %d\n\n", sdu_coc_mbuf_mempool_rx.mp_num_free, sdu_coc_mbuf_mempool_tx.mp_num_free);
}

int l2cap_coc_accept(uint16_t conn_handle, uint16_t peer_mtu, struct ble_l2cap_chan *chan){
    struct os_mbuf *sdu_rx;

    printf("LE CoC accepting, chan: 0x%08x, peer_mtu %d\n", (uint32_t) chan, peer_mtu);

    // Commented for mbedtls uses:

    // sdu_rx = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool_rx, 0);
    // if(!sdu_rx){
    //     return BLE_HS_ENOMEM;
    // }

    // return ble_l2cap_recv_ready(chan, sdu_rx);

    return 0;
}

void l2cap_coc_unstalled(uint16_t conn_handle, struct ble_l2cap_chan *chan){
    struct l2cap_conn *conn;
    struct l2cap_coc_node *coc;
    struct l2cap_coc_node *cur;

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
        printf("COC doesn't exist\n");
        return;
    }

    xSemaphoreGive(coc->unstalled_semaphore);
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
        sdu_rx[i] = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool_rx, 0);
        assert(sdu_rx != NULL);
    }

    if(num == 1){
        return ble_l2cap_connect(conn_handle, psm, mtu, sdu_rx[0], on_l2cap_event, NULL);
    }

    return ble_l2cap_enhanced_connect(conn_handle, psm, mtu, num, sdu_rx,on_l2cap_event, NULL);
}

int l2cap_disconnect(uint16_t conn_handle, uint16_t coc_idx){
    struct l2cap_conn *conn;
    struct l2cap_coc_node *coc;
    int i;
    int rc = 0;

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    i = 0;
    SLIST_FOREACH(coc, &conn->coc_list, next){
        if(i == coc_idx){
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
    struct l2cap_coc_node *coc;
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

int l2cap_send(uint16_t conn_handle, uint16_t coc_idx, const unsigned char* data, uint16_t len){
    struct l2cap_coc_node *coc;
    struct l2cap_conn *conn;
    struct os_mbuf *sdu_tx;
    static int packet_count = 0; // TODO DEBUG remove

    printf("mempool free blocks: rx = %d, tx = %d\n", sdu_coc_mbuf_mempool_rx.mp_num_free, sdu_coc_mbuf_mempool_tx.mp_num_free);

    printf("Sending L2CAP packet #%d: connection = %d, COC = %d, len = %d\n", packet_count++, conn_handle, coc_idx, len);

    sdu_tx = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool_tx, 0);
    if (!sdu_tx) {
        printf("ERROR: Unable to allocate mbuf!\n\n");
        return -1;
    }

    conn = l2cap_conn_find(conn_handle);
    assert(conn != NULL);

    coc = l2cap_coc_find_by_idx(conn, coc_idx);
    if(coc == NULL){
        printf("COC = %d doesn't exist!\n\n", coc_idx);
        return -1;
    }

    int res = os_mbuf_append(sdu_tx, data, len);
    if (res != 0) {
        os_mbuf_free_chain(sdu_tx);
        printf("ERROR: Unable to append data! (%i)\n\n", res);
        // NimBLE return code
        return res;
    }

    // do {
    //     ble_hs_lock();
    //     res = ble_l2cap_send(coc->chan, sdu_tx);
    //     ble_hs_unlock();
    //     // TODO other solution to locking/unlocking may be a queue?
    // } while (res == BLE_HS_EBUSY);

    // Send L2CAP packet. If host is busy (that's when the COC module is still stalled with data), wait for it using a semaphore, that is obtained when the COC runs the unstalled-event.
    int semaphore_res;
    do{
        res = ble_l2cap_send(coc->chan, sdu_tx);
        if(res == BLE_HS_EBUSY || res == BLE_HS_ESTALLED){
            semaphore_res = xSemaphoreTake(coc->unstalled_semaphore, portMAX_DELAY);
            if(semaphore_res == pdTRUE){
                printf("COC got unstalled.\n");
            }else{
                printf("COC is probably still stalled. Timeout on semaphore.\n");
            }
        }
    }
    while(res == BLE_HS_EBUSY);

    if (res != 0) {
        if(res == BLE_HS_ESTALLED){
            // Don't free the mbuf chain of sdu_tx here because it seems like it will be freed automatically when the COC is unstalling.
            printf("COC is stalled\n");
        }else{
            os_mbuf_free_chain(sdu_tx);
            printf("ERROR: Unable to send SDU! (%i)\n", res);
        }
    }

    printf("mempool free blocks: rx = %d, tx = %d\n\n", sdu_coc_mbuf_mempool_rx.mp_num_free, sdu_coc_mbuf_mempool_tx.mp_num_free);
    return res;
}

/*** Read Buffer (mbuf pool) ***/

size_t l2cap_read_rx_buffer(unsigned char* data, size_t len, sdu_queue* queue){
    int res;
    struct os_mbuf* sdu = sdu_queue_get(queue);
    
    // Calculate the amount of unread bytes in the current SDU.
    sdu_queue_offset_t unread_bytes_in_cur_sdu = sdu->om_len - queue->front_offset;

    // Check if the amount of bytes we have to read reaches over multiple SDUs of sdu_os_mbuf_pool_rx.
    if(len > unread_bytes_in_cur_sdu){
        // We have to read multiple SDUs.
        size_t bytes_read = 0;
        while(len > bytes_read){
            // Read all the unread bytes starting at the offset of the current SDU.
            for(int i = 0; i < unread_bytes_in_cur_sdu; i++){
                data[bytes_read + i] = sdu->om_data[queue->front_offset + i];
            }
            bytes_read += unread_bytes_in_cur_sdu;


            // Did read all the unread bytes of the current SDU. Now remove the SDU and get the next SDU.
            res = os_mbuf_free_chain(sdu);
            assert(res == 0);
            res = sdu_queue_remove(queue); // Sets queue.front_offset to 0 automatically.
            assert(res == 0);
            sdu = sdu_queue_get(queue);
            if(sdu == NULL){
                // queue is empty -> did read all the data from the SDUs in sdu_os_mbuf_pool_rx  -> report mbedTLS how many bytes we read so far
                break;
            }
            
            // Calculate if we have to read the complete next SDU.
            if((len - bytes_read) >= sdu->om_len){
                // We have to read the complete next SDU.
                unread_bytes_in_cur_sdu = sdu->om_len;
            }else{
                // We have to read a part of the next SDU only.
                unread_bytes_in_cur_sdu = len - bytes_read;
                // Read all the unread bytes starting at the offset of the current SDU.
                for(int i = 0; i < unread_bytes_in_cur_sdu; i++){
                    data[bytes_read + i] = sdu->om_data[queue->front_offset + i];
                }
                bytes_read += unread_bytes_in_cur_sdu;
                break;
            }
        }
        return bytes_read;
    }else{
        // The amount of the unread bytes is placed in the front SDU only

        // Read the data starting at the offset of the currenct SDU.
        for(int i = 0; i < len; i++){
            data[i] = sdu->om_data[queue->front_offset + i];
        }

        if(len < unread_bytes_in_cur_sdu){
            // We didn't have to read all remaining bytes of the SDU.
            // Add the amount of bytes we did read to the offset.
            sdu_queue_increase_offset(queue, len);
        }
        else{
            // We had to read all remaining bytes. Now remove the SDU.
            res = os_mbuf_free_chain(sdu);
            assert(res == 0);
            res = sdu_queue_remove(queue); // Sets queue.front_offset to 0 automatically.
            assert(res == 0);
        }
        return len;
    }
}

// TODO REMOVE
int l2cap_send_old_from_btshell(uint16_t conn_handle, uint16_t coc_idx, const unsigned char* data, uint16_t len){
    struct l2cap_conn *conn;
    struct l2cap_coc_node *coc;
    struct os_mbuf *sdu_tx;
    int i;
    int rc;

    printf("conn=%d, coc_idx=%d, len=%d\n", conn_handle, coc_idx, len);

    conn = l2cap_conn_find(conn_handle);
    if(conn == NULL){
        printf("conn=%d does not exist\n", conn_handle);
        return 0;
    }

    i = 0;
    SLIST_FOREACH(coc, &conn->coc_list, next){
        if(i == coc_idx){
            break;
        }
        i++;
    }
    if(coc == NULL){
        printf("Are you sure your channel exist?\n");
        return 0;
    }

    sdu_tx = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool_tx, 0);
    if (sdu_tx == NULL) {
        printf("No memory in the test sdu pool\n");
        return 0;
    }

    rc = os_mbuf_append(sdu_tx, data, len);
    if(rc){
        printf("Cannot append data %i !\n", i);
        os_mbuf_free_chain(sdu_tx);
        return rc;
    }

    rc = ble_l2cap_send(coc->chan, sdu_tx);
    if(rc){
        if(rc == BLE_HS_ESTALLED){
          printf("CoC module is stalled with data. Wait for unstalled \n");
        }else{
            printf("Could not send data rc=%d\n", rc);
            os_mbuf_free_chain(sdu_tx); // TODO STALL ISSUE: In btshell example os_mbuf_free_chain(sdu_tx) was NOT called here.
        }
        // TODO STALL ISSUE: In btshell example os_mbuf_free_chain(sdu_tx) was called here. In this case the client would receive an empty packet, if a previous call of l2cap_send is still stalling the channel
    }

    return rc;
}