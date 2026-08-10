// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_NET_SOCKET_HPP_
#define SLOWHTTP_NET_SOCKET_HPP_

#include <cstddef>

struct addrinfo;

namespace slowhttp {

enum class SockState { Init, Connecting, Connected, Closed, Error };

// Thin owning wrapper over a non-blocking TCP socket. Plain TCP only in M0; a
// TlsBackend slots in at send_some()/recv_some() for M1 without changing callers.
class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  // Movable so it can live in a std::vector (transfers fd ownership).
  Socket(Socket&& other) noexcept : fd_(other.fd_), state_(other.state_) {
    other.fd_ = -1;
    other.state_ = SockState::Init;
  }
  Socket& operator=(Socket&& other) noexcept {
    if (this != &other) {
      close();
      fd_ = other.fd_;
      state_ = other.state_;
      other.fd_ = -1;
      other.state_ = SockState::Init;
    }
    return *this;
  }

  // Begins a non-blocking connect. `recv_buffer`, when > 0, is applied as
  // SO_RCVBUF *before* connect() -- required for it to shrink the advertised TCP
  // window during the handshake. Returns false on immediate failure.
  bool start_connect(const addrinfo* addr, int recv_buffer = 0);

  // Actual SO_RCVBUF the kernel settled on, or -1 if unavailable. Kernels clamp
  // to a minimum and commonly return double what was requested, so the effective
  // window is usually larger than asked for; callers should report this rather
  // than assume the requested value took effect.
  int recv_buffer_size() const;
  // Call when the socket reports writable while Connecting; checks SO_ERROR.
  bool finish_connect();

  // Returns bytes written (>= 0; 0 means would-block), or -1 on fatal error.
  long send_some(const char* data, std::size_t len);
  // Returns bytes read (> 0), 0 on peer close (EOF), -1 on would-block,
  // -2 on fatal error.
  long recv_some(char* buf, std::size_t len);

  void close();

  int fd() const { return fd_; }
  SockState state() const { return state_; }

 private:
  int fd_ = -1;
  SockState state_ = SockState::Init;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_NET_SOCKET_HPP_
