
#include "testlib.h"

//TODO: fix pathing
#include "/home/mrm/Arduino/hardware/espressif/esp32/tools/sdk/include/mbedtls/mbedtls/ecdh.h"

void check(int error_code){
  if(error_code != 0)
    Serial.println(error_code, HEX);
}

void setup() {
  Serial.begin(115200);

  //Testing STS and ECDH stuff
  //ECDH Context:
  mbedtls_ecdh_context *ctx;
  mbedtls_ecdh_init(ctx);
  
  //ECP Group:
  // mbedtls_ecp_group *grp:  mbedtls_ecp_load() or mbedtls_ecp_tls_read_group()
  mbedtls_ecp_group *grp;
  mbedtls_ecp_group_init(grp);
  mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_CURVE25519);

  
}

void loop() {
  Serial.println("Test");
  delay(5000);
}
