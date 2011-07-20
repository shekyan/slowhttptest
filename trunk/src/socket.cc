// Wrappers around sockets.
//
// (c) Victor Agababov (vagababov@gmail.com) 2011
// Apache license goes here.

#include "socket.h"
#include "slowlog.h"
#include <unistd.h>

namespace slowhttptest {

Socket::Socket() : the_socket_(-1) {
}

Socket::~Socket() {
  Close();
}

void Socket::Close() {
  if (the_socket_ >= 0) {
    ::shutdown(the_socket_, SHUT_RDWR);
    ::close(the_socket_);
    the_socket_ = -1;
  }
}

int Socket::Send(const char* data, const int size) {
  check(the_socket_ >= 0, "Not Connected"); 
  return ::send(the_socket_, data, size, 0);
}

int Socket::Recv(char* data, const int size) {
  check(the_socket_ >= 0, "Not Connected"); 
  return ::recv(the_socket_, data, size, 0);
}

bool Socket::Init(const addrinfo* addr) {
  CHECK_NOTNULL(addr);
  const int sock = ::socket(addr->ai_family, addr->ai_socktype,
                            addr->ai_protocol);
  check(sock != -1, "Sockets cannot be created");
  const int ret = ::connect(sock, addr->ai_addr, addr->ai_addrlen);
  return ret == 0;
}

Socket* Socket::Create(const addrinfo* addr) {
  CHECK_NOTNULL(addr);
  Socket* sock = new Socket();
  if (!sock->Init(addr)) {
    delete sock;
    sock = NULL;
  }
  return sock;
}

}  // namespace slowhttptest
