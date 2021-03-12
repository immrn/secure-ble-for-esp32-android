// Source: https://github.com/ARMmbed/mbedtls/blob/development/programs/pkey/ecdh_curve25519.c

#include "sbea_ecdh.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

void cleanup(mbedtls_ecdh_context *_ctx_srv, mbedtls_ecdh_context *_ctx_cli, mbedtls_ctr_drbg_context *_ctr_drbg, mbedtls_entropy_context *_entropy, int _exit_code){
  mbedtls_ecdh_free( _ctx_srv );
  mbedtls_ecdh_free( _ctx_cli );
  mbedtls_ctr_drbg_free( _ctr_drbg );
  mbedtls_entropy_free(   _entropy );

  mbedtls_exit( _exit_code );
}

void sbea_ecdh_example(){
  int ret = 1;
  int exit_code = MBEDTLS_EXIT_FAILURE;
  mbedtls_ecdh_context ctx_cli, ctx_srv;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  unsigned char cli_to_srv[32], srv_to_cli[32];
  const char pers[] = "ecdh";

  mbedtls_ecdh_init( &ctx_cli );
  mbedtls_ecdh_init( &ctx_srv );
  mbedtls_ctr_drbg_init( &ctr_drbg );

  //Initialize random number generation
  mbedtls_printf( "  . Seeding the random number generator..." );
  fflush( stdout );

  mbedtls_entropy_init( &entropy );
  if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof pers ) ) != 0 )
  {
      mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
      cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  mbedtls_printf( " ok\n" );

  //Client: initialize context and generate keypair
  mbedtls_printf( "  . Setting up client context..." );
  fflush( stdout );

  ret = mbedtls_ecp_group_load( &ctx_cli.grp, MBEDTLS_ECP_DP_CURVE25519 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_ecdh_gen_public( &ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q,
                                 mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_mpi_write_binary( &ctx_cli.Q.X, cli_to_srv, 32 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  mbedtls_printf( " ok\n" );

  //Server: initialize context and generate keypair
  mbedtls_printf( "  . Setting up server context..." );
  fflush( stdout );

  ret = mbedtls_ecp_group_load( &ctx_srv.grp, MBEDTLS_ECP_DP_CURVE25519 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_ecdh_gen_public( &ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q,
                                 mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_mpi_write_binary( &ctx_srv.Q.X, srv_to_cli, 32 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  mbedtls_printf( " ok\n" );

  //Server: read peer's key and generate shared secret
  mbedtls_printf( "  . Server reading client key and computing secret..." );
  fflush( stdout );

  ret = mbedtls_mpi_lset( &ctx_srv.Qp.Z, 1 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.X, cli_to_srv, 32 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_ecdh_compute_shared( &ctx_srv.grp, &ctx_srv.z,
                                     &ctx_srv.Qp, &ctx_srv.d,
                                     mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  mbedtls_printf( " ok\n" );

  //Client: read peer's key and generate shared secret
  mbedtls_printf( "  . Client reading server key and computing secret..." );
  fflush( stdout );

  ret = mbedtls_mpi_lset( &ctx_cli.Qp.Z, 1 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.X, srv_to_cli, 32 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  ret = mbedtls_ecdh_compute_shared( &ctx_cli.grp, &ctx_cli.z,
                                     &ctx_cli.Qp, &ctx_cli.d,
                                     mbedtls_ctr_drbg_random, &ctr_drbg );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  mbedtls_printf( " ok\n" );

  //Verification: are the computed secrets equal?
  mbedtls_printf( "  . Checking if both computed secrets are equal..." );
  fflush( stdout );

  ret = mbedtls_mpi_cmp_mpi( &ctx_cli.z, &ctx_srv.z );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
    cleanup(&ctx_srv, &ctx_cli, &ctr_drbg, &entropy, exit_code);
  }

  mbedtls_printf( " ok\n" );

  exit_code = MBEDTLS_EXIT_SUCCESS;
}