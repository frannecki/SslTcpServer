#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "SslServer.h"

using namespace std::placeholders;

static const int kMaxBufferLen = 1024;
static char err_msg[kMaxBufferLen];

#define exit_err                                                    \
  fprintf(stderr, "[%s:%u %s] ", __FILE__, __LINE__, __FUNCTION__); \
  exit_err_msg

static void exit_err_msg(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(err_msg, sizeof(err_msg), fmt, args);
  va_end(args);
  perror(err_msg);
  exit(EXIT_FAILURE);
}

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

static SslConnection* AcceptSocket(int serverfd, int pollfd) {
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

  SslConnection* conn =
      new SslConnection(clientfd, std::string(ip_addr, strlen(ip_addr)), port);

  struct epoll_event evt;
  evt.data.fd = clientfd;
  evt.data.ptr = conn;
  evt.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
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

  if (pollfd_ < 0) {
    exit_err("epoll_create1");
  }
  struct epoll_event evt;
  evt.data.fd = serverfd_;
  evt.events = EPOLLIN;
  if (epoll_ctl(pollfd_, EPOLL_CTL_ADD, serverfd_, &evt) < 0) {
    exit_err("epoll_ctl");
  }
}

SslServer::~SslServer() { close(serverfd_); }

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
          SslConnection* conn = AcceptSocket(serverfd_, pollfd_);
          conn->set_read_callback(message_callback_);
          conn->set_want_write_callback(
              std::bind(&SslServer::PollOnWrite, this, _1, _2));
          conn->set_close_callback(
              std::bind(&SslServer::CloseConnection, this, _1));
          connections_.insert(std::pair<int, SslConnection*>(conn->fd(), conn));
          if (connection_callback_) connection_callback_(conn);
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

void SslServer::set_connection_callback(
    const std::function<void(SslConnection*)>& callback) {
  connection_callback_ = callback;
}

void SslServer::set_message_callback(
    const std::function<void(SslConnection*, Buffer*)>& callback) {
  message_callback_ = callback;
}

void SslServer::PollOnWrite(SslConnection* conn, bool want_write) {
  uint32_t revents = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
  struct epoll_event evt;
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
                             uint16_t peer_port)
    : clientfd_(fd), peer_ip_(peer_ip_addr), peer_port_(peer_port) {}

SslConnection::~SslConnection() {
  if (close(clientfd_) < 0) {
    exit_err("close");
  }
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
    char buffer[kMaxBufferLen];
    int ret = recv(clientfd_, buffer, kMaxBufferLen, 0);
    if (ret > 0) {
      in_buffer_.Write(std::string(buffer, ret));
      if (read_callback_) read_callback_(this, &in_buffer_);
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
