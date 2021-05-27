#ifndef _FILE_SUBSCRIPTION_H_
#define _FILE_SUBSCRIPTION_H_

#include "app_ssl_ctx.h"
#include "app_io_ctx.h"

/** @brief      TODO
 *
 *  @return     TODO
 */
int verify_subscription(ssl_ctx* ctx);

/** @brief      TODO
 *
 *  @return     TODO
 */
int send_subscription(ssl_ctx* ctx);

/** @brief      Await L2CAP COC connection and try to perform a TLS handshake.
 */
void test_mbedtls_1(io_ctx* io, ssl_ctx* ssl_context);



#endif /* !_FILE_SUBSCRIPTION_H */