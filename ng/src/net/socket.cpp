// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "net/socket.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <netinet/tcp_fsm.h>
#endif

#include <cerrno>
#include <cstdio>
#include <utility>

namespace slowhttp {
namespace {

bool set_nonblocking(int fd) {
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// A proxy that answers CONNECT with anything but 2xx has refused the tunnel, and
// the body it sends is an error page, not the origin. Parsing just the status
// line is enough to tell those apart.
bool connect_reply_ok(const std::string& reply, std::string& why) {
  auto eol = reply.find("\r\n");
  std::string status = reply.substr(0, eol == std::string::npos ? 0 : eol);
  if (status.rfind("HTTP/", 0) != 0) {
    why = "proxy sent a non-HTTP reply to CONNECT";
    return false;
  }
  auto sp = status.find(' ');
  if (sp == std::string::npos || status.size() < sp + 4) {
    why = "proxy sent a malformed status line: " + status;
    return false;
  }
  if (status[sp + 1] != '2') {
    why = "proxy refused CONNECT: " + status;
    return false;
  }
  return true;
}

constexpr std::size_t kMaxConnectReply = 16384;

}  // namespace

Socket::Socket(Socket&& other) noexcept
    : fd_(other.fd_),
      state_(other.state_),
      plan_(std::move(other.plan_)),
      connect_sent_(other.connect_sent_),
      connect_reply_(std::move(other.connect_reply_)),
      setup_error_(std::move(other.setup_error_)),
      connect_errno_(other.connect_errno_),
      tls_(std::move(other.tls_)) {
  other.fd_ = -1;
  other.state_ = SockState::Init;
  other.connect_sent_ = 0;
}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    close();
    fd_ = other.fd_;
    state_ = other.state_;
    plan_ = std::move(other.plan_);
    connect_sent_ = other.connect_sent_;
    connect_reply_ = std::move(other.connect_reply_);
    setup_error_ = std::move(other.setup_error_);
    connect_errno_ = other.connect_errno_;
    tls_ = std::move(other.tls_);
    other.fd_ = -1;
    other.state_ = SockState::Init;
    other.connect_sent_ = 0;
  }
  return *this;
}

Socket::~Socket() { close(); }

bool Socket::start_connect(const addrinfo* addr, int recv_buffer) {
  return start_connect(addr, recv_buffer, SetupPlan{});
}

bool Socket::start_connect(const addrinfo* addr, int recv_buffer,
                           const SetupPlan& plan) {
  plan_ = plan;
  connect_sent_ = 0;
  connect_reply_.clear();
  setup_error_.clear();
  connect_errno_ = 0;
  tls_.reset();

  fd_ = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  if (fd_ < 0) {
    connect_errno_ = errno;
    state_ = SockState::Error;
    return false;
  }
  if (!set_nonblocking(fd_)) {
    connect_errno_ = errno;
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
  // Abortive close: send RST and destroy the socket, rather than the graceful
  // FIN handshake with its FIN_WAIT and TIME_WAIT states.
  //
  // Two reasons, both measured rather than assumed. Closing thousands of remote
  // sockets gracefully means the kernel transmits a FIN per connection and then
  // waits on retransmit timers, which is why cancelling a run against a remote
  // target could take minutes while the identical run against loopback exited
  // instantly. And a graceful close leaves every local port in TIME_WAIT for
  // minutes afterwards, which exhausts the ephemeral range and makes the *next*
  // run fail to connect.
  //
  // The cost is that a peer sees RST instead of FIN. For a tool whose
  // connections are abandoned by design that is both accurate and closer to what
  // a real vanishing client does.
  int rc = ::connect(fd_, addr->ai_addr, addr->ai_addrlen);
  if (rc == 0) {
    enter_setup();
    return true;
  }
  if (errno == EINPROGRESS) {
    state_ = SockState::Connecting;
    return true;
  }
  connect_errno_ = errno;
  close();
  state_ = SockState::Error;
  return false;
}

bool Socket::finish_connect() {
  int err = 0;
  socklen_t len = sizeof(err);
  if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
    // SO_ERROR carries why the asynchronous connect failed; getsockopt failing
    // is itself the answer if it does not.
    connect_errno_ = err != 0 ? err : errno;
    close();
    state_ = SockState::Error;
    return false;
  }
  enter_setup();
  return true;
}

void Socket::enter_setup() {
  if (!plan_.connect_request.empty()) {
    state_ = SockState::ProxyConnect;
    return;
  }
  if (plan_.tls) {
    state_ = SockState::TlsHandshake;
    return;
  }
  state_ = SockState::Connected;
}

SetupIo Socket::continue_setup() {
  switch (state_) {
    case SockState::ProxyConnect:  return drive_proxy_connect();
    case SockState::TlsHandshake:  return drive_tls_handshake();
    case SockState::Connected:     return SetupIo::Done;
    default:                       return SetupIo::Error;
  }
}

SetupIo Socket::drive_proxy_connect() {
  // Phase 1: push out the CONNECT request, possibly across several calls.
  while (connect_sent_ < plan_.connect_request.size()) {
    long n = raw_send(plan_.connect_request.data() + connect_sent_,
                      plan_.connect_request.size() - connect_sent_);
    if (n > 0) {
      connect_sent_ += static_cast<std::size_t>(n);
    } else if (n == 0) {
      return SetupIo::WantWrite;
    } else {
      setup_error_ = "write to proxy failed";
      return SetupIo::Error;
    }
  }

  // Phase 2: read the reply headers one byte at a time. A chunked read would
  // overshoot "\r\n\r\n" and swallow the first bytes the origin sent — which for
  // https is the start of the TLS record layer, and losing those is unrecoverable.
  // The reply is a few dozen bytes and happens once per connection, so the extra
  // syscalls are not worth avoiding with a peek-and-scan.
  for (;;) {
    char buf[1];
    long n = raw_recv(buf, sizeof(buf));
    if (n > 0) {
      connect_reply_.append(buf, static_cast<std::size_t>(n));
      if (connect_reply_.size() > kMaxConnectReply) {
        setup_error_ = "proxy CONNECT reply headers too large";
        return SetupIo::Error;
      }
      if (connect_reply_.size() >= 4 &&
          connect_reply_.compare(connect_reply_.size() - 4, 4, "\r\n\r\n") == 0) {
        std::string why;
        if (!connect_reply_ok(connect_reply_, why)) {
          setup_error_ = why;
          return SetupIo::Error;
        }
        // Tunnel is open. TLS, if any, now runs inside it.
        if (plan_.tls) {
          state_ = SockState::TlsHandshake;
          return drive_tls_handshake();
        }
        state_ = SockState::Connected;
        return SetupIo::Done;
      }
    } else if (n == -1) {
      return SetupIo::WantRead;
    } else {
      setup_error_ = n == 0 ? "proxy closed the connection during CONNECT"
                            : "read from proxy failed";
      return SetupIo::Error;
    }
  }
}

SetupIo Socket::drive_tls_handshake() {
  if (!tls_.active()) {
    std::string err;
    if (!tls_.attach(plan_.tls, fd_, plan_.sni, err)) {
      setup_error_ = err;
      return SetupIo::Error;
    }
  }
  switch (tls_.handshake()) {
    case TlsIo::Done:
      state_ = SockState::Connected;
      return SetupIo::Done;
    case TlsIo::WantRead:  return SetupIo::WantRead;
    case TlsIo::WantWrite: return SetupIo::WantWrite;
    case TlsIo::Error:
    default:
      setup_error_ = "TLS handshake failed: " + tls_.last_error();
      return SetupIo::Error;
  }
}

std::string Socket::tls_description() const { return tls_.description(); }

bool Socket::peer_has_closed() const {
  if (fd_ < 0) return false;

#if defined(__APPLE__) && defined(TCP_CONNECTION_INFO)
  // Darwin. tcpi_state carries the TCPS_* values from <netinet/tcp_fsm.h>.
  tcp_connection_info info;
  socklen_t len = sizeof(info);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) != 0)
    return false;
  switch (info.tcpi_state) {
    case TCPS_CLOSE_WAIT:   // peer sent FIN, we have not closed -- the case
    case TCPS_LAST_ACK:     // that accumulates in the thousands
    case TCPS_CLOSING:
    case TCPS_TIME_WAIT:
    case TCPS_CLOSED:
      return true;
    default:
      return false;
  }
#elif defined(__linux__) && defined(TCP_INFO)
  // Linux numbers the states differently from BSD, so the constants cannot be
  // shared: TCP_CLOSE_WAIT is 8 here and 5 there.
  struct tcp_info info;
  socklen_t len = sizeof(info);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_INFO, &info, &len) != 0) return false;
  switch (info.tcpi_state) {
    case TCP_CLOSE_WAIT:
    case TCP_LAST_ACK:
    case TCP_CLOSING:
    case TCP_TIME_WAIT:
    case TCP_CLOSE:
      return true;
    default:
      return false;
  }
#else
  return false;  // no query available; detection is simply absent
#endif
}

int Socket::recv_buffer_size() const {
  if (fd_ < 0) return -1;
  int val = 0;
  socklen_t len = sizeof(val);
  if (::getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &val, &len) < 0) return -1;
  return val;
}

long Socket::raw_send(const char* data, std::size_t len) {
  ssize_t n = ::send(fd_, data, len, 0);
  if (n >= 0) return n;
  if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
  return -1;
}

long Socket::raw_recv(char* buf, std::size_t len) {
  ssize_t n = ::recv(fd_, buf, len, 0);
  if (n > 0) return n;
  if (n == 0) return 0;  // peer performed orderly shutdown
  if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
  return -2;
}

long Socket::send_some(const char* data, std::size_t len) {
  if (tls_.active()) return tls_.send_some(data, len);
  return raw_send(data, len);
}

long Socket::recv_some(char* buf, std::size_t len) {
  if (tls_.active()) return tls_.recv_some(buf, len);
  return raw_recv(buf, len);
}

void Socket::close() {
  // Free the SSL object before the fd it refers to.
  tls_.reset();
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
  if (state_ != SockState::Error) state_ = SockState::Closed;
}

}  // namespace slowhttp
