// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include "net/socket.hpp"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Which TCP header supplies struct tcp_info, and what it is allowed to contain.
//
// glibc's <netinet/tcp.h> is the only header that defines both struct tcp_info
// and the TCP_* state constants this file needs, but its copy of the struct is
// frozen at the 3.x-era layout: it ends at tcpi_total_retrans and has never
// carried tcpi_bytes_sent (glibc only synced the kernel's extended struct in
// December 2025, so every glibc in support today -- 2.36 through 2.41 --
// lacks the field). The kernel's own <linux/tcp.h> has had it since 4.18, but
// the two headers cannot be included together (both define struct tcphdr, and
// the redefinition is an error), and the kernel's has no TCP_* state constants.
// So this file takes glibc's, asks the compiler whether the struct it got
// carries the bytes-sent counter (detail::HasTcpiBytesSent below), and reports
// the counter as unavailable where it does not -- the same "absent rather than
// wrong" answer the other TCP_INFO queries give on platforms without them.
#include <netinet/tcp.h>

#if defined(__APPLE__)
#include <netinet/tcp_fsm.h>
#endif

#include <cerrno>
#include <cstdio>
#include <string>
#include <type_traits>
#include <utility>

namespace slowhttp {
namespace detail {

// Whether the struct tcp_info this build sees carries tcpi_bytes_sent. The
// kernel added the field in 4.18, but userspace copies of the struct vary in
// age (see the include note at the top of this file), so presence is a property
// of the headers, not of the platform.
template <class T, class = void>
struct HasTcpiBytesSent : std::false_type {};
template <class T>
struct HasTcpiBytesSent<
    T, std::void_t<decltype(std::declval<T&>().tcpi_bytes_sent)>>
    : std::true_type {};

// Reads tcp_info's bytes-sent counter, or -1 where the struct this build sees
// does not carry it. A pair of constrained overloads rather than `if constexpr`
// at the call site: the call site is not a template, and a discarded
// `if constexpr` branch is still semantically checked outside one.
template <class T, std::enable_if_t<HasTcpiBytesSent<T>::value, int> = 0>
long tx_bytes(const T& info) {
  return static_cast<long>(info.tcpi_bytes_sent);
}
template <class T, std::enable_if_t<!HasTcpiBytesSent<T>::value, int> = 0>
long tx_bytes(const T&) {
  return -1;
}

}  // namespace detail
}  // namespace slowhttp

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
  // Writing to a connection the peer has already closed must return EPIPE, not
  // raise SIGPIPE and kill the process. Investigated as a possible cause of slow
  // teardown and cleared: runs with it disabled were indistinguishable.
  int on = 1;
  ::setsockopt(fd_, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
  // Nothing else is set here on purpose, and SO_LINGER in particular is not.
  //
  // Forcing an abortive close -- SO_LINGER {1, 0}, so the stack sends RST
  // instead of FIN -- looks like the obvious way to make teardown cheap, and it
  // is the opposite. Measured against a remote peer, alternating the two arms
  // within one session so both saw the same network, closing 1500 established
  // connections took:
  //
  //     abortive (RST)   2.29s   30.90s   47.89s
  //     graceful (FIN)   0.30s    0.59s    0.07s
  //
  // Every stall was in the abortive arm, each one blocking close(2) for very
  // close to exactly one second; the graceful arm's worst single close was
  // 19 ms. A quantised one-second wait is a timeout rather than work, and it
  // gets worse run over run, which suggests something on the path is accounting
  // for the resets. The peer sees FIN, the operator waits a fraction of a
  // second, and both are better outcomes.
  //
  // The classic tool sets only SO_RCVBUF and O_NONBLOCK and has run this
  // workload for fifteen years, which pointed the right way the whole time.
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

// Bytes sitting unread in the receive buffer, or -1 if it cannot be asked.
// Slow read exists to leave this number high, so it is the first thing to
// correlate against when some closes are expensive and others are free.
long Socket::unread_bytes() const {
  if (fd_ < 0) return -1;
  int n = 0;
  if (::ioctl(fd_, FIONREAD, &n) != 0) return -1;
  return n;
}

// The raw TCP state, for attributing behaviour to it rather than guessing.
// Returns -1 where the platform offers no way to ask. The numbering is the
// platform's own and is not comparable across them -- callers report it, they do
// not interpret it.
int Socket::tcp_state() const {
  if (fd_ < 0) return -1;
#if defined(__APPLE__) && defined(TCP_CONNECTION_INFO)
  tcp_connection_info info;
  socklen_t len = sizeof(info);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) != 0)
    return -1;
  return info.tcpi_state;
#elif defined(__linux__) && defined(TCP_INFO)
  struct tcp_info info;
  socklen_t len = sizeof(info);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_INFO, &info, &len) != 0) return -1;
  return info.tcpi_state;
#else
  return -1;
#endif
}

long Socket::kernel_tx_bytes() const {
  if (fd_ < 0) return -1;
#if defined(__APPLE__) && defined(TCP_CONNECTION_INFO)
  tcp_connection_info i;
  socklen_t len = sizeof(i);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_CONNECTION_INFO, &i, &len) != 0)
    return -1;
  return static_cast<long>(i.tcpi_txbytes);
#elif defined(__linux__) && defined(TCP_INFO)
  struct tcp_info i;
  socklen_t len = sizeof(i);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_INFO, &i, &len) != 0) return -1;
  // Whichever header supplied struct tcp_info may predate the bytes-sent
  // counters (see the include note at the top of this file). Report the
  // counter as unavailable where it does, which the caller reads as "cannot
  // be asked" -- the same answer a platform with no TCP_INFO at all gives.
  return detail::tx_bytes(i);
#else
  return -1;
#endif
}

std::string Socket::tcp_diag() const {
  if (fd_ < 0) return {};
#if defined(__APPLE__) && defined(TCP_CONNECTION_INFO)
  tcp_connection_info i;
  socklen_t len = sizeof(i);
  if (::getsockopt(fd_, IPPROTO_TCP, TCP_CONNECTION_INFO, &i, &len) != 0)
    return {};
  char buf[320];
  // snd_sbbytes is the one worth staring at: bytes still sitting in the send
  // socket buffer, in-flight data included. A close that has to dispose of
  // those takes a different path from one that does not.
  std::snprintf(buf, sizeof(buf),
                "state=%u snd_sb=%u snd_wnd=%u cwnd=%u rcv_wnd=%u rto=%u"
                " srtt=%u tx=%llu rtx=%llu rx=%llu flags=0x%x",
                i.tcpi_state, i.tcpi_snd_sbbytes, i.tcpi_snd_wnd,
                i.tcpi_snd_cwnd, i.tcpi_rcv_wnd, i.tcpi_rto, i.tcpi_srtt,
                (unsigned long long)i.tcpi_txbytes,
                (unsigned long long)i.tcpi_txretransmitbytes,
                (unsigned long long)i.tcpi_rxbytes, i.tcpi_flags);
  return buf;
#else
  return {};
#endif
}

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

int Socket::release_fd() {
  tls_.reset();  // free the SSL object before the fd it refers to
  const int fd = fd_;
  fd_ = -1;
  if (state_ != SockState::Error) state_ = SockState::Closed;
  return fd;
}

// Plain close, and deliberately so. See the note in start_connect: SO_LINGER
// with a zero timeout was tried twice here and is measurably worse.
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
