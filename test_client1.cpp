#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "utils.h"

static const int kMaxBufferOutLen = 4096;

char buff[kMaxBufferLen] = "areyouokdude?";
char sock_buff_in[kMaxBufferLen] = {0};
char sock_buff_out[kMaxBufferLen] = {0};

char buff_in[kMaxBufferLen] = {0};
char buff_out[kMaxBufferOutLen] = {0};
int buff_out_len = 0;

SSL_CTX* ssl_ctx;
SSL* ssl;
BIO *rbio, *wbio;

void Encrypt() {
  char ssl_buffer[kMaxBufferLen];
  while (buff_out_len < kMaxBufferOutLen) {
    int buff_out_capacity = kMaxBufferOutLen - buff_out_len;
    if (buff_out_capacity > kMaxBufferLen) {
      buff_out_capacity = kMaxBufferLen;
    }
    int n_ssl_read = BIO_read(wbio, ssl_buffer, buff_out_capacity);

    if (n_ssl_read > 0) {
      memcpy(buff_out + buff_out_len, ssl_buffer, n_ssl_read);
      buff_out_len += n_ssl_read;
    } else {
      break;
    }
  }
}

void HandleSslError(int err) {
  switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      Encrypt();
      break;
    case SSL_ERROR_SSL:
      exit_err("ssl error");
    default:
      break;
  }
}

int main(int argc, char** argv) {
  int ret;
  ssl_init();
  ssl_ctx = create_context(false);

  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
    exit_err("fcntl");
  }

  struct sockaddr_in addr;
  socklen_t addr_len;
  if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) < 0) {
    perror("inet_pton");
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = ntohs(8080);
  addr_len = sizeof(addr);
  int n_connect = connect(fd, (struct sockaddr*)&addr, addr_len);
  if (n_connect < 0) {
    switch (errno) {
      case EINPROGRESS:
        break;
      default:
        exit_err("connect");
    }
  }

  fprintf(stdout, "Connected to server\n");

  ssl = SSL_new(ssl_ctx);
  rbio = BIO_new(BIO_s_mem());
  wbio = BIO_new(BIO_s_mem());
  SSL_set_bio(ssl, rbio, wbio);
  SSL_set_connect_state(ssl);

  struct pollfd poll_fd;
  poll_fd.fd = fd;
  poll_fd.events = POLLIN | POLLRDHUP | POLLOUT;

  bool message_sent = false;

  while (1) {
    bool want_write = false;
    int ret = poll(&poll_fd, 1, -1);
    if (ret < 0) {
      exit_err("poll");
    }
    if (poll_fd.revents & POLLHUP) {
      fprintf(stdout, "Connection shutdown\n");
      break;
    }
    if (poll_fd.revents & (POLLIN | POLLRDHUP)) {
      int n_read = recv(fd, sock_buff_in, kMaxBufferLen, 0);
      if (n_read < 0) {
        continue;
      } else if (n_read == 0) {
        fprintf(stdout, "Peer shutdown\n");
        break;
      }
      int n_cur = 0;
      while (n_cur < n_read) {
        int n = BIO_write(rbio, sock_buff_in + n_cur, n_read - n_cur);
        if (n > 0) {
          n_cur += n;
        } else {
          break;
        }
      }
      if (!SSL_is_init_finished(ssl)) {
        int n_ssl_connect = SSL_do_handshake(ssl);
        if (n_ssl_connect < 0) {
          HandleSslError(SSL_get_error(ssl, n_ssl_connect));
        }
        want_write = true;
      } else {
        int n_ssl_read = SSL_read(ssl, buff_in, kMaxBufferLen);
        if (n_ssl_read <= 0) {
          int err = SSL_get_error(ssl, n_ssl_read);
          HandleSslError(err);
        } else {
          buff_in[n_ssl_read] = 0;
          fprintf(stdout, "Received %d bytes: %s\n", n_ssl_read, buff_in);
        }
      }
    }
    if (poll_fd.revents & POLLOUT) {
      if (!SSL_is_init_finished(ssl)) {
        int n_ssl_connect = SSL_do_handshake(ssl);
        if (n_ssl_connect < 0) {
          HandleSslError(SSL_get_error(ssl, n_ssl_connect));
        }
        want_write = true;
      } else if (!message_sent) {
        message_sent = true;
        int len = strlen(buff);
        int n_cur = 0;
        while (n_cur < len) {
          int n = SSL_write(ssl, buff + n_cur, len - n_cur);
          if (n > 0) {
            n_cur += n;
          } else {
            exit_err("BIO_write");
          }
        }
        Encrypt();
      }

      while (buff_out_len > 0) {
        int n_written = send(fd, buff_out, buff_out_len, 0);
        if (n_written > 0) {
          memmove(buff_out, buff_out + n_written, buff_out_len - n_written);
          buff_out_len -= n_written;
        } else if (n_written < 0) {
          switch (errno) {
            case EAGAIN:
#if EWOULDBLOCK != EAGAIN
            case EWOULDBLOCK:
#endif
              want_write = true;
              break;
            default:
              exit_err("send");
          }
        }
      }
    }
    if (want_write)
      poll_fd.events |= POLLOUT;
    else
      poll_fd.events &= (~POLLOUT);
  }

  close(fd);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);

  return 0;
}
