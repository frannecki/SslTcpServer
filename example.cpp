#include "SslServer.h"

using namespace std::placeholders;

void OnMessage(ssl_server::SslConnection* conn, ssl_server::Buffer* buffer) {
  std::string str = buffer->ReadAll();
  fprintf(stdout, "Received %lu bytes: %s\n", str.size(), str.c_str());
  // conn->Send("Reply: " + str);
  conn->Send(
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
      "26\r\n\r\nHello this is SslTcpServer");
}

int main(int argc, char** argv) {
  ssl_server::Init();
  ssl_server::SslServer server(0, 8080);
  server.set_message_callback(std::bind(OnMessage, _1, _2));
  server.Run();
  ssl_server::CleanUp();
}
