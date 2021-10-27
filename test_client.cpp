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

int main(int argc, char** argv) {
  int ret;
  char buff[kMaxBufferLen] = "areyouokdude?";

  ssl_init();
  SSL_CTX* ssl_ctx = create_context(false);

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

  SSL* ssl = SSL_new(ssl_ctx);
  SSL_set_fd(ssl, fd);
  SSL_set_connect_state(ssl);

  // int n_ssl_connect = SSL_do_handshake(ssl);

  struct pollfd poll_fd;
  poll_fd.fd = fd;
  poll_fd.events = POLLIN | POLLRDHUP | POLLOUT;

  while (1) {
    bool want_write = false;
    int ret = poll(&poll_fd, 1, -1);
    if (ret < 0) {
      exit_err("poll");
    }
    if (poll_fd.revents & POLLHUP) {
      break;
    }
    if (poll_fd.revents & (POLLIN | POLLRDHUP)) {
      int n_read = SSL_read(ssl, buff, kMaxBufferLen);
      if (n_read < 0) {
        continue;
      } else if (n_read == 0) {
        break;
      } else {
        buff[n_read] = 0;
        fprintf(stdout, "Received %d bytes: %s\n", n_read, buff);
      }
    }
    if (poll_fd.revents & POLLOUT) {
      if (!SSL_is_init_finished(ssl)) {
        int n_ssl_connect = SSL_do_handshake(ssl);
        want_write = true;
      } else {
        SSL_write(ssl, buff, strlen(buff));
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
