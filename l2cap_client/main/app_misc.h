#include <inttypes.h>
#include "os/os_mbuf.h"

void print_addr(const void *addr);

void print_bytes(const uint8_t *bytes, int len);

void print_mbuf(const struct os_mbuf *om);