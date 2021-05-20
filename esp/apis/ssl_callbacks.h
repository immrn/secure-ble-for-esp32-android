#include <stdint.h>
#include <stddef.h>


// Callbacks for mbedtls

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
