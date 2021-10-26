#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "SslServer.h"
#include "utils.h"

using namespace std::placeholders;

namespace ssl_server {

static const int kMaxBufferLen = 1024;

void Init() {
  fprintf(stdout, "Initializing ssl utilities.\n");
  ssl_init();
}

void CleanUp() { EVP_cleanup(); }

Buffer::Buffer() : read_index_(0), write_index_(0) {}

std::string Buffer::ReadAll() {
  std::string result;
  result.assign(buffer_.begin() + read_index_, buffer_.begin() + write_index_);
  write_index_ = read_index_ = 0;
  return result;
}

void Buffer::Write(const std::string& buf) {
  std::copy(buf.begin(), buf.end(),
            std::inserter(buffer_, buffer_.begin() + write_index_));
  write_index_ += buf.size();
}

void Buffer::HaveRead(uint32_t n) {
  // n bytes have been read
  int readable = std::min(n, write_index_ - read_index_);
  read_index_ += readable;
  if (read_index_ >= write_index_) {
    write_index_ = read_index_ = 0;
  }
}

int Buffer::Peek(char* buf, int len) {
  int readable = 0;
  readable = std::min(static_cast<uint32_t>(len), write_index_ - read_index_);
  memcpy(buf, buffer_.data(), readable);
  return readable;
}

int Buffer::ReadableBytes() { return write_index_ - read_index_; }

bool Buffer::Empty() const { return read_index_ == write_index_; }

static SslConnection* AcceptSocket(int serverfd, int pollfd, SSL_CTX* ssl_ctx) {
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  int clientfd =
      ::accept4(serverfd, (struct sockaddr*)&addr, &addr_len, SOCK_NONBLOCK);
  if (clientfd < 0) {
    exit_err("accept4");
  }

  char ip_addr[20] = {0};
  inet_ntop(AF_INET, &addr.sin_addr, ip_addr, sizeof(ip_addr));
  uint16_t port = htons(addr.sin_port);
  fprintf(stdout, "Accepted connection from %s:%u\n", ip_addr, port);

  SslConnection* conn = new SslConnection(
      clientfd, std::string(ip_addr, strlen(ip_addr)), port, ssl_ctx);

  struct epoll_event evt;
  memset(&evt, 0, sizeof(evt));
  evt.data.fd = clientfd;
  evt.data.ptr = conn;
  evt.events = EPOLLIN | EPOLLRDHUP;
  if (epoll_ctl(pollfd, EPOLL_CTL_ADD, clientfd, &evt) < 0) {
    exit_err("epoll_ctl");
  }
  return conn;
}

SslServer::SslServer(uint32_t ip, uint16_t port)
    : serverfd_(socket(AF_INET, SOCK_STREAM, 0)), pollfd_(epoll_create1(0)) {
  if (serverfd_ < 0) {
    exit_err("socket");
  }
  int enable = 1;
  if (setsockopt(serverfd_, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) <
      0) {
    exit_err("setsockopt");
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(ip);
  addr.sin_port = htons(port);
  socklen_t addr_len = sizeof(addr);
  if (bind(serverfd_, (struct sockaddr*)&addr, addr_len) < 0) {
    exit_err("bind");
  }
  if (listen(serverfd_, 0) < 0) {
    exit_err("listen");
  }

  fprintf(stdout, "Listening on port %u. fd = %d\n", port, serverfd_);

  if (pollfd_ < 0) {
    exit_err("epoll_create1");
  }
  struct epoll_event evt;
  memset(&evt, 0, sizeof(evt));
  evt.data.fd = serverfd_;
  evt.events = EPOLLIN;
  if (epoll_ctl(pollfd_, EPOLL_CTL_ADD, serverfd_, &evt) < 0) {
    exit_err("epoll_ctl");
  }

  ssl_ctx_ = create_context();
  configure_context(ssl_ctx_);
}

SslServer::~SslServer() {
  close(serverfd_);
  SSL_CTX_free(ssl_ctx_);
}

void SslServer::Run() {
  while (1) {
    int ret = epoll_wait(pollfd_, evts_, kMaxPollEventNum, -1);
    if (ret < 0) {
      exit_err("epoll_wait");
    }
    for (int idx = 0; idx < ret; ++idx) {
      int fd = evts_[idx].data.fd;
      uint32_t revents = evts_[idx].events;
      if (fd == serverfd_) {
        if (revents & EPOLLIN) {
          SslConnection* conn = AcceptSocket(serverfd_, pollfd_, ssl_ctx_);
          if (connections_.size() + 1 >= kMaxPollEventNum) {
            struct linger lo = { 1, 0 };
            // reset connection
            setsockopt(conn->fd(), SOL_SOCKET, SO_LINGER, &lo, sizeof(lo));
            delete conn;
            continue;
          }
          conn->set_read_callback(message_callback_);
          conn->set_want_write_callback(
              std::bind(&SslServer::PollOnWrite, this, _1, _2));
          conn->set_close_callback(
              std::bind(&SslServer::CloseConnection, this, _1));
          connections_.insert(std::pair<int, SslConnection*>(conn->fd(), conn));
        }
      } else {
        // Getting bad descriptor evts_[idx].data.fd here
        SslConnection* conn =
            reinterpret_cast<SslConnection*>(evts_[idx].data.ptr);
        if (conn) {
          conn->HandleEvents(revents);
        }
      }
    }
  }
}

void SslServer::set_message_callback(
    const std::function<void(SslConnection*, Buffer*)>& callback) {
  message_callback_ = callback;
}

void SslServer::PollOnWrite(SslConnection* conn, bool want_write) {
  uint32_t revents = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
  struct epoll_event evt;
  memset(&evt, 0, sizeof(evt));
  if (want_write) {
    revents |= EPOLLOUT;
  }
  evt.data.fd = conn->fd();
  evt.data.ptr = conn;
  evt.events = revents;
  if (epoll_ctl(pollfd_, EPOLL_CTL_MOD, conn->fd(), &evt) < 0) {
    exit_err("epoll_ctl");
  }
}

void SslServer::CloseConnection(int fd) {
  auto iter = connections_.find(fd);
  if (iter != connections_.end()) {
    fprintf(stdout, "Closing connection with %s:%u\n",
            iter->second->peer_ip().c_str(), iter->second->peer_port());
    delete iter->second;
    connections_.erase(iter);
  }
}

SslConnection::SslConnection(int fd, const std::string& peer_ip_addr,
                             uint16_t peer_port, SSL_CTX* ssl_ctx)
    : clientfd_(fd),
      peer_ip_(peer_ip_addr),
      peer_port_(peer_port),
      ssl_engine_(SSL_new(ssl_ctx)),
      in_bio_(BIO_new(BIO_s_mem())),
      out_bio_(BIO_new(BIO_s_mem())) {
  SSL_set_accept_state(ssl_engine_);
  SSL_set_bio(ssl_engine_, in_bio_, out_bio_);
}

SslConnection::~SslConnection() {
  if (close(clientfd_) < 0) {
    exit_err("close");
  }
  SSL_free(ssl_engine_);
  // BIO_free(in_bio_);
  // BIO_free(out_bio_);
  ssl_engine_ = nullptr;
  in_bio_ = out_bio_ = nullptr;
}

bool SslConnection::Send(const std::string& buf) {
  if (!SSL_is_init_finished(ssl_engine_)) {
    return true;
  }
  // encrypt all data
  int len = buf.size();
  int n_written = 0;
  while (n_written < len) {
    int n = SSL_write(ssl_engine_, buf.c_str() + n_written, len - n_written);
    if (n > 0) {
      n_written += n;
      this->Encrypt();
    } else {
      break;
    }
  }

  return Send();
}

void SslConnection::Shutdown() {
  if (shutdown(clientfd_, SHUT_WR) < 0) {
    exit_err("shutdown");
  }
}

void SslConnection::HandleEvents(uint32_t revents) {
  if (revents & (EPOLLERR | EPOLLHUP)) {
    if (close_callback_) close_callback_(clientfd_);
    return;
  }
  if (revents & EPOLLOUT) {
    if (!Send()) return;
  }
  if (revents & (EPOLLIN | EPOLLRDHUP)) {
    char sock_buffer[kMaxBufferLen];
    int ret = recv(clientfd_, sock_buffer, kMaxBufferLen, 0);

    if (ret > 0) {
      int cur = 0;

      while (cur < ret) {
        int n = BIO_write(in_bio_, sock_buffer + cur, ret - cur);
        if (n <= 0) {
          exit_err("BIO_write");
        }
        cur += n;

        if (!SSL_is_init_finished(ssl_engine_)) {
          int n_accepted = SSL_do_handshake(ssl_engine_);

          if (n_accepted > 0) {
            fprintf(stdout, "SSL handshake finished for client %s:%u\n",
                    peer_ip_.c_str(), peer_port_);
          }

          if (HandleSslError(n_accepted) < 0) {
            close_callback_(clientfd_);
            return;
          }

          if (!SSL_is_init_finished(ssl_engine_)) {
            continue;
          }
        }

        int n_read = this->Decrypt();
        if (HandleSslError(n_read) < 0) {
          close_callback_(clientfd_);
          return;
        }
      }
    } else if (ret == 0) {
      Shutdown();
    } else {
      switch (errno) {
        case ECONNRESET:
          close_callback_(clientfd_);
          return;
        default:
          exit_err("recv. errno: %d", errno);
      }
      exit_err("recv. errno: %d", errno);
    }
  }
}

void SslConnection::Encrypt() {
  char ssl_buffer[kMaxBufferLen];
  int n_ssl_read;
  while (1) {
    n_ssl_read = BIO_read(out_bio_, ssl_buffer, kMaxBufferLen);

    if (n_ssl_read > 0) {
      out_buffer_.Write(std::string(ssl_buffer, n_ssl_read));
    } else {
      break;
    }
  }

  // this is necessary for ssl server hello to be sent out
  if (want_write_callback_) want_write_callback_(this, true);
}

int SslConnection::Decrypt() {
  char ssl_buffer[kMaxBufferLen];
  int n_read;
  while (1) {
    n_read = SSL_read(ssl_engine_, ssl_buffer, kMaxBufferLen);
    if (n_read <= 0) break;
    in_buffer_.Write(std::string(ssl_buffer, n_read));
    if (read_callback_) read_callback_(this, &in_buffer_);
  }
  return n_read;
}

int SslConnection::HandleSslError(int n) {
  if (n > 0) return 1;
  int err = SSL_get_error(ssl_engine_, n);
  switch (err) {
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      // might be ssl renegotiation
      this->Encrypt();
      break;
    default:
      return -1;
  }
  return 0;
}

int SslConnection::fd() const { return clientfd_; }

const std::string& SslConnection::peer_ip() const { return peer_ip_; }

uint16_t SslConnection::peer_port() const { return peer_port_; }

void SslConnection::set_close_callback(
    const std::function<void(int)>& callback) {
  close_callback_ = callback;
}

void SslConnection::set_read_callback(
    const std::function<void(SslConnection*, Buffer*)>& callback) {
  read_callback_ = callback;
}

void SslConnection::set_want_write_callback(
    const std::function<void(SslConnection*, bool)>& callback) {
  want_write_callback_ = callback;
}

bool SslConnection::Send() {
  std::string buf = out_buffer_.ReadAll();
  uint32_t nbytes = 0;
  int n = 0;
  while (nbytes < buf.size() && n >= 0) {
    n = send(clientfd_, buf.c_str() + nbytes, buf.size(), 0);
    if (n >= 0) {
      nbytes += n;
    } else {
      switch (errno) {
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
          if (want_write_callback_) want_write_callback_(this, true);
          break;
        case ECONNRESET:
          close_callback_(clientfd_);
          return false;
        default:
          exit_err("send. errno: %d", errno);
      }
    }
  }
  if (n >= 0 && want_write_callback_) want_write_callback_(this, false);
  out_buffer_.HaveRead(nbytes);
  return true;
}

}  // namespace ssl_server
