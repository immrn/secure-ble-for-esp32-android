#ifndef _FILE_DEBUG_L2CAP_H_
#define _FILE_DEBUG_L2CAP_H_

#include <stdlib.h>

#include "app_io_ctx.h"

int debug_l2cap_send(io_ctx* io, const unsigned char* data, size_t len);

int debug_l2cap_recv(io_ctx* io, unsigned char* data, size_t len);

int test_l2cap_tx(io_ctx* io);

int test_l2cap_rx(io_ctx* io);



#endif /* !_FILE_DEBUG_L2CAP_H_ */