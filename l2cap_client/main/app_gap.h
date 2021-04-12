#include <stdint.h>
//#include <stdio.h>
#include "esp_nimble_hci.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"

#include "app_misc.h"

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

int adv_start(uint8_t own_addr_type, const ble_addr_t *direct_addr, int32_t duration_ms, const struct ble_gap_adv_params *params, bool restart);

int adv_stop(void);

int adv_restart(struct ble_gap_event *event);

void print_conn_desc(const struct ble_gap_conn_desc *desc);

void print_adv_fields(const struct ble_hs_adv_fields *fields);

void decode_adv_data(const uint8_t *adv_data, uint8_t adv_data_len, void *arg);

int on_gap_event(struct ble_gap_event *event, void *arg);