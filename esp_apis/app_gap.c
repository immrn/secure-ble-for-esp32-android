#include "app_gap.h"

int init_gap_adv_fields(){
    struct ble_hs_adv_fields fields;
    const char *name;

    /**
     *  Set the advertisement data included in our advertisements:
     *     o Flags (indicates advertisement type and other general info).
     *     o Advertising tx power.
     *     o Device name.
     *     o 16-bit service UUIDs (alert notifications).
     */

    memset(&fields, 0, sizeof(fields));

    // Advertise two flags: Discoverability in forthcoming advertisement (general) BLE-only (BR/EDR unsupported)
    fields.flags = BLE_HS_ADV_F_DISC_GEN |
                   BLE_HS_ADV_F_BREDR_UNSUP;

    fields.tx_pwr_lvl_is_present = 1;
    fields.tx_pwr_lvl = BLE_HS_ADV_TX_PWR_LVL_AUTO;

    name = ble_svc_gap_device_name();
    fields.name = (uint8_t *)name;
    fields.name_len = strlen(name);
    fields.name_is_complete = 1;

    // fields.uuids16 = (ble_uuid16_t[]) {
    //     BLE_UUID16_INIT(GATT_SVR_SVC_ALERT_UUID)
    // };
    // fields.num_uuids16 = 1;
    // fields.uuids16_is_complete = 1;

    return ble_gap_adv_set_fields(&fields);
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

void print_adv_fields(const struct ble_hs_adv_fields *fields){
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

void decode_adv_data(const uint8_t *adv_data, uint8_t adv_data_len, void *arg){
    struct ble_hs_adv_fields fields;

    printf(" data_length=%d data=", adv_data_len);
    print_bytes(adv_data, adv_data_len);

    printf(" fields:\n");
    ble_hs_adv_parse_fields(&fields, adv_data, adv_data_len);
    print_adv_fields(&fields);
}

