#ifndef _FILE_APP_L2CAP_IO_CALLS_H_
#define _FILE_APP_L2CAP_IO_CALLS_H_

#include <stdint.h>
#include <stddef.h>


// Callbacks for mbedtls (have a look at ssl_ctx_create)

/** @brief      Callback for mbedtls. Use it as parameter in ssl_create_ctx().
 *
 *  @return     Returns the bytes sent or -1 if sending failed at L2CAP.
 */
int l2cap_io_send_data(void* ctx, const unsigned char* data, size_t len);

/** @brief      Callback for mbedtls. Use is as parameter in ssl_create_ctx().
 *
 *  @return     Returns the bytes read or MBEDTLS_ERR_SSL_TIMEOUT.
 */
int l2cap_io_recv_data(void* ctx, unsigned char* data, size_t len, uint32_t timeout_msec);



#endif /* !_FILE_APP_L2CAP_IO_CALLS_H_ */