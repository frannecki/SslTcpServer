#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include <functional>
#include <map>
#include <vector>

#include <openssl/bio.h>
#include <sys/epoll.h>

class Buffer {
 public:
  Buffer();
  std::string ReadAll();
  void Write(const std::string& buf);
  void HaveRead(uint32_t n);
  int Peek(char* buf, int len);
  int ReadableBytes();
  bool Empty() const;

 private:
  uint32_t read_index_, write_index_;
  std::vector<char> buffer_;
};

class SslConnection {
 public:
  SslConnection(int fd, const std::string& peer_ip_addr, uint16_t peer_port);
  SslConnection(const SslConnection&) = delete;
  ~SslConnection();
  template <typename T>
  bool Send(T&& buf) {
    out_buffer_.Write(std::forward<T>(buf));
    return Send();
  }
  void Shutdown();
  void HandleEvents(uint32_t revents);
  int fd() const;
  const std::string& peer_ip() const;
  uint16_t peer_port() const;
  void set_close_callback(const std::function<void(int)>& callback);
  void set_read_callback(
      const std::function<void(SslConnection*, Buffer*)>& callback);
  void set_want_write_callback(
      const std::function<void(SslConnection*, bool)>& callback);

 private:
  bool Send();

  int clientfd_;
  std::string peer_ip_;
  uint16_t peer_port_;
  BIO* in_bio_;
  BIO* out_bio_;
  Buffer in_buffer_;
  Buffer out_buffer_;
  std::function<void(int)> close_callback_;
  std::function<void(SslConnection*, Buffer*)> read_callback_;
  // for epoll EPOLLOUT notification
  std::function<void(SslConnection*, bool)> want_write_callback_;
};

static const int kMaxPollEventNum = 256;

class SslServer {
 public:
  SslServer(uint32_t ip, uint16_t port);
  SslServer(const SslServer&) = delete;
  ~SslServer();
  void Run();
  void set_connection_callback(
      const std::function<void(SslConnection*)>& callback);
  void set_message_callback(
      const std::function<void(SslConnection*, Buffer*)>& callback);

 private:
  void PollOnWrite(SslConnection* conn, bool want_write);
  void CloseConnection(int fd);

  int serverfd_;
  int pollfd_;
  std::function<void(SslConnection*)> connection_callback_;
  std::function<void(SslConnection*, Buffer*)> message_callback_;
  std::map<int, SslConnection*> connections_;
  struct epoll_event evts_[kMaxPollEventNum];
};

#endif
