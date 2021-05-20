#include <stdint.h>

// I/O Context for mbedtls
typedef struct{
    struct l2cap_conn* conn;
    uint16_t coc_idx;               // COC index
} io_ctx;