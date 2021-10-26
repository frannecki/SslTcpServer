#include <openssl/err.h>
#include <openssl/ssl.h>

#define exit_err                                                    \
  fprintf(stderr, "[%s:%u %s] ", __FILE__, __LINE__, __FUNCTION__); \
  exit_err_msg

static const int kMaxBufferLen = 1024;
static char err_msg[kMaxBufferLen];

static void exit_err_msg(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(err_msg, sizeof(err_msg), fmt, args);
  va_end(args);
  perror(err_msg);
  exit(EXIT_FAILURE);
}

void ssl_init() {
  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
}

SSL_CTX *create_context(bool server = true) {
  SSL_CTX *ctx;

  if (server)
    ctx = SSL_CTX_new(SSLv23_server_method());
  else
    ctx = SSL_CTX_new(SSLv23_client_method());

  if (!ctx) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

namespace ssl_server {

void configure_context(SSL_CTX *ctx) {
  SSL_CTX_set_ecdh_auto(ctx, 1);

  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, "ssl/cert.pem", SSL_FILETYPE_PEM) <=
      0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "ssl/key.pem", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
}

}  // namespace ssl_server
