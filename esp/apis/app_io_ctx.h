#ifndef _FILE_APP_IO_CTX_H_
#define _FILE_APP_IO_CTX_H_

#include <stdint.h>

// I/O Context for mbedtls
typedef struct{
    struct l2cap_conn* conn;
    uint16_t coc_idx;               // COC index
} io_ctx;



#endif /* !_FILE_APP_IO_CTX_H_ */