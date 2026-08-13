// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_NET_SOCKET_HPP_
#define SLOWHTTP_NET_SOCKET_HPP_

#include <cstddef>
#include <memory>
#include <string>

#include "slowhttp/tls.hpp"

struct addrinfo;

namespace slowhttp {

// ProxyConnect and TlsHandshake are *setup* phases: the TCP connection exists but
// is not yet usable by an attack. Both are driven by continue_setup().
enum class SockState {
  Init,
  Connecting,
  ProxyConnect,
  TlsHandshake,
  Connected,
  Closed,
  Error
};

// What continue_setup() wants next. Mirrors TlsIo because a CONNECT tunnel and a
// TLS handshake have the same shape: make progress, or say which readiness to
// wait for.
enum class SetupIo { Done, WantRead, WantWrite, Error };

// Everything that has to happen between a completed TCP connect and the first
// attack byte. Empty plan == plain HTTP straight to the origin.
//
// The order matters and is fixed: CONNECT tunnel first, TLS inside it. Putting
// tunnel establishment here rather than in the engine keeps it below the
// send_some()/recv_some() abstraction — by the time an attack writes a byte, the
// bytes on the wire are already tunnelled and encrypted, and no attack has to
// know either happened.
struct SetupPlan {
  std::string connect_request;      // full CONNECT request, or empty for none
  std::shared_ptr<TlsContext> tls;  // non-null => handshake after the tunnel
  std::string sni;                  // SNI/verification name for the handshake

  bool empty() const { return connect_request.empty() && !tls; }
};

// Thin owning wrapper over a non-blocking TCP socket, optionally tunnelled
// through an HTTP proxy and optionally wrapped in TLS. Callers above
// send_some()/recv_some() see none of that.
class Socket {
 public:
  Socket() = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  // Movable so it can live in a std::vector (transfers fd ownership).
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  // Begins a non-blocking connect. `recv_buffer`, when > 0, is applied as
  // SO_RCVBUF *before* connect() -- required for it to shrink the advertised TCP
  // window during the handshake. Returns false on immediate failure.
  bool start_connect(const addrinfo* addr, int recv_buffer = 0);
  bool start_connect(const addrinfo* addr, int recv_buffer,
                     const SetupPlan& plan);

  // Actual SO_RCVBUF the kernel settled on, or -1 if unavailable. Kernels clamp
  // to a minimum and commonly return double what was requested, so the effective
  // window is usually larger than asked for; callers should report this rather
  // than assume the requested value took effect.
  int recv_buffer_size() const;
  // Call when the socket reports writable while Connecting; checks SO_ERROR.
  // On success the state moves to the first pending setup phase, or straight to
  // Connected when the plan is empty.
  bool finish_connect();

  // Drives ProxyConnect / TlsHandshake one step. Returns Done once the socket is
  // Connected and ready for attack bytes.
  SetupIo continue_setup();

  // Whether the peer has closed its half of the connection, asked of the TCP
  // state machine rather than inferred from reading.
  //
  // Slow read exists precisely to not read, so it cannot notice a FIN the usual
  // way: the buffered response sits ahead of the end-of-stream, and MSG_PEEK
  // cannot tell "data pending" from "data then FIN". Draining to find out would
  // undo the attack. Asking the kernel for the connection state answers it
  // directly and consumes nothing.
  //
  // Returns false where the platform offers no such query, which costs only the
  // detection -- never a false positive.
  bool peer_has_closed() const;

  // Platform-numbered TCP state, or -1 if unavailable. Diagnostic only.
  int tcp_state() const;

  // errno from the failed socket()/connect(), or the SO_ERROR a failed
  // asynchronous connect reported. 0 when nothing has failed.
  //
  // Kept because the *reason* decides who is at fault. EMFILE means this process
  // ran out of descriptors; ECONNREFUSED means the target said no. Reporting
  // both as "could not connect" points the operator at the wrong machine.
  int connect_errno() const { return connect_errno_; }

  // Why setup failed, for diagnostics. Empty when nothing has failed.
  const std::string& setup_error() const { return setup_error_; }
  // e.g. "TLSv1.3 / TLS_AES_256_GCM_SHA384"; empty for plain connections.
  std::string tls_description() const;

  // Returns bytes written (>= 0; 0 means would-block), or -1 on fatal error.
  long send_some(const char* data, std::size_t len);
  // Returns bytes read (> 0), 0 on peer close (EOF), -1 on would-block,
  // -2 on fatal error.
  long recv_some(char* buf, std::size_t len);

  void close();

  int fd() const { return fd_; }
  SockState state() const { return state_; }
  // True once the socket carries attack traffic (past every setup phase).
  bool ready() const { return state_ == SockState::Connected; }

 private:
  // Raw fd I/O, bypassing TLS. Used by the CONNECT exchange, which happens
  // before the TLS layer exists.
  long raw_send(const char* data, std::size_t len);
  long raw_recv(char* buf, std::size_t len);

  // Moves from a completed TCP connect into the first pending setup phase.
  void enter_setup();
  SetupIo drive_proxy_connect();
  SetupIo drive_tls_handshake();

  int fd_ = -1;
  SockState state_ = SockState::Init;

  SetupPlan plan_;
  std::size_t connect_sent_ = 0;  // bytes of the CONNECT request already written
  std::string connect_reply_;     // accumulated CONNECT response headers
  std::string setup_error_;
  int connect_errno_ = 0;
  TlsSession tls_;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_NET_SOCKET_HPP_
