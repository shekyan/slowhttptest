// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "net/socket.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>

namespace slowhttp {
namespace {

bool set_nonblocking(int fd) {
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

}  // namespace

Socket::~Socket() { close(); }

bool Socket::start_connect(const addrinfo* addr, int recv_buffer) {
  fd_ = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  if (fd_ < 0) {
    state_ = SockState::Error;
    return false;
  }
  if (!set_nonblocking(fd_)) {
    close();
    state_ = SockState::Error;
    return false;
  }
  // Must precede connect(): the receive buffer size is what the stack advertises
  // as its window during the handshake. Setting it also disables receive-buffer
  // autotuning on Linux, which is exactly what we want to keep the window small.
  if (recv_buffer > 0) {
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &recv_buffer, sizeof(recv_buffer));
    // Deliberately not fatal: kernels clamp this to their own minimum and the
    // attack still works with a larger-than-requested window, just less sharply.
  }
#ifdef SO_NOSIGPIPE
  int on = 1;
  ::setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
  int rc = ::connect(fd_, addr->ai_addr, addr->ai_addrlen);
  if (rc == 0) {
    state_ = SockState::Connected;
    return true;
  }
  if (errno == EINPROGRESS) {
    state_ = SockState::Connecting;
    return true;
  }
  close();
  state_ = SockState::Error;
  return false;
}

bool Socket::finish_connect() {
  int err = 0;
  socklen_t len = sizeof(err);
  if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
    close();
    state_ = SockState::Error;
    return false;
  }
  state_ = SockState::Connected;
  return true;
}

int Socket::recv_buffer_size() const {
  if (fd_ < 0) return -1;
  int val = 0;
  socklen_t len = sizeof(val);
  if (::getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &val, &len) < 0) return -1;
  return val;
}

long Socket::send_some(const char* data, std::size_t len) {
  ssize_t n = ::send(fd_, data, len, 0);
  if (n >= 0) return n;
  if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
  return -1;
}

long Socket::recv_some(char* buf, std::size_t len) {
  ssize_t n = ::recv(fd_, buf, len, 0);
  if (n > 0) return n;
  if (n == 0) return 0;  // peer performed orderly shutdown
  if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
  return -2;
}

void Socket::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  if (state_ != SockState::Error) state_ = SockState::Closed;
}

}  // namespace slowhttp
