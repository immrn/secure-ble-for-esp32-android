#include <stdint.h>
#include "esp_nimble_hci.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"

#include "app_misc.h"


int init_gap_adv_fields();

void print_conn_desc(const struct ble_gap_conn_desc *desc);

void print_adv_fields(const struct ble_hs_adv_fields *fields);

void decode_adv_data(const uint8_t *adv_data, uint8_t adv_data_len, void *arg);

int on_gap_event(struct ble_gap_event *event, void *arg);