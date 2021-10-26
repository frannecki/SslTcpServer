# SslTcpServer: A tiny ssl tcp server
This is an example web server using ssl over tcp for encryption. Non-blocking socket is used here.

## Usage

### Generate RSA certificate and key
```sh
mkdir -p ssl
openssl req -x509 -nodes -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365
```

### Build and run
Aside from the example server, a [demo client](test_client.cpp) is provided for testing.
```sh
# compile server
./build.sh

# start server, and open https://<ip>:8080 in your browser
./build/server

# compile example client
mkdir -p build
g++ -o ./build/client client.cpp -lcrypto -lssl
```

## References
* [Simple TLS Server](https://wiki.openssl.org/index.php/Simple_TLS_Server)
* [OpenSSL example using memory BIO with non-blocking socket IO](https://gist.github.com/darrenjs/4645f115d10aa4b5cebf57483ec82eca)
