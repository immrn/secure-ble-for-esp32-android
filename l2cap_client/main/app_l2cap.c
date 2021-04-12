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
    int idx = l2cap_conn_find_idx(handle);
    if(idx == -1){
        return NULL;
    }else{
        return l2cap_conns + idx;
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

void l2cap_conn_delete_idx(int idx){
    assert(idx >= 0 && idx < l2cap_conns_num);

    for(int i = idx + 1; i < l2cap_conns_num; i++){
        l2cap_conns[i - 1] = l2cap_conns[i];
    }

    l2cap_conns_num--;
}

/*** l2cap coc ***/

int l2cap_coc_add(uint16_t conn_handle, struct ble_l2cap_chan *chan){
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

void l2cap_coc_remove(uint16_t conn_handle, struct ble_l2cap_chan *chan){
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

void l2cap_coc_recv(struct ble_l2cap_chan *chan, struct os_mbuf *sdu){
    printf("LE CoC SDU received, chan: 0x%08x, data len %d\n", (uint32_t) chan, OS_MBUF_PKTLEN(sdu));

    os_mbuf_free_chain(sdu);
    sdu = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool, 0);
    assert(sdu != NULL);

    if(ble_l2cap_recv_ready(chan, sdu) != 0){
        assert(0);
    }
}

int l2cap_coc_accept(uint16_t conn_handle, uint16_t peer_mtu, struct ble_l2cap_chan *chan){
    struct os_mbuf *sdu_rx;

    printf("LE CoC accepting, chan: 0x%08x, peer_mtu %d\n", (uint32_t) chan, peer_mtu);

    sdu_rx = os_mbuf_get_pkthdr(&sdu_os_mbuf_pool, 0);
    if(!sdu_rx){
        return BLE_HS_ENOMEM;
    }

    return ble_l2cap_recv_ready(chan, sdu_rx);
}

void l2cap_coc_unstalled(uint16_t conn_handle, struct ble_l2cap_chan *chan){
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
