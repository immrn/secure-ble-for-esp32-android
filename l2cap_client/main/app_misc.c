#include "app_misc.h"

void print_addr(const void *addr){
    const uint8_t *u8p;

    u8p = addr;
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        u8p[5], u8p[4], u8p[3], u8p[2], u8p[1], u8p[0]);
}

void print_bytes(const uint8_t *bytes, int len){
    for(int i = 0; i < len; i++){
        printf("%s0x%02x", i != 0 ? ":" : "", bytes[i]);
    }
}

void print_mbuf(const struct os_mbuf *om){
    int colon = 0;
    while(om != NULL){
        if(colon){
            printf(":");
        }else{
            colon = 1;
        }
        print_bytes(om->om_data, om->om_len);
        om = SLIST_NEXT(om, om_next);
    }
}

void print_mbuf_as_string(const struct os_mbuf* om){
    while(om != NULL){
        for(int i = 0; i < om->om_len; i++){
            printf("%c", om->om_data[i]);
        }
        om = SLIST_NEXT(om, om_next);
    }
    printf("\n");
}