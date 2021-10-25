#!/bin/bash
mkdir -p build
g++ -Wall -std=c++11 -g -o build/server example.cpp SslServer.cpp -lcrypto -lssl
