#include "SslServer.h"

using namespace std::placeholders;

void OnConnection(SslConnection* conn) {
  conn->Send("Hello~ This is ssl server.");
}

void OnMessage(SslConnection* conn, Buffer* buffer) {
  std::string str = buffer->ReadAll();
  fprintf(stdout, "Received %lu bytes: %s\n", str.size(), str.c_str());
  conn->Send("Reply: " + str);
}

int main(int argc, char** argv) {
  SslServer server(0, 8080);
  server.set_connection_callback(std::bind(OnConnection, _1));
  server.set_message_callback(std::bind(OnMessage, _1, _2));
  server.Run();
}
