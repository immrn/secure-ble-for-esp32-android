#include <stdint.h>

#include "ssl_ctx.h"


// I/O Context for mbedtls
typedef struct{
    struct l2cap_conn* conn;
    uint16_t coc_idx;               // COC index
} io_ctx;


/*  @brief      Callback for mbedtls. Use it as parameter in ssl_create_ctx().
 *
 *  @return     Returns the bytes sent or -1 if sending failed at L2CAP.
 */
int send_data(void* ctx, const unsigned char* data, size_t len);

/*  @brief      Callback for mbedtls. Use is as parameter in ssl_create_ctx().
 *
 *  @return     Returns the bytes read or MBEDTLS_ERR_SSL_TIMEOUT.
 */
int recv_data(void* ctx, unsigned char* data, size_t len, uint32_t timeout_msec);

/*  @brief      TODO
 *
 *  @return     TODO
 */
int verify_subscription(ssl_ctx* ctx);

/*  @brief      TODO
 *
 *  @return     TODO
 */
int send_subscription(ssl_ctx* ctx);

/*  @brief      Await L2CAP COC connection and try to perform a TLS handshake.
 */
void test_mbedtls_1(io_ctx* io, ssl_ctx* ssl_context);