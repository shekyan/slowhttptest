// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_TLS_HPP_
#define SLOWHTTP_TLS_HPP_

#include <cstddef>
#include <memory>
#include <string>

namespace slowhttp {

// Result of a non-blocking TLS operation that has not necessarily finished.
// WantRead/WantWrite tell the engine which readiness to wait for; OpenSSL can
// ask to *write* while reading and vice versa, which is why this is not simply
// "would block".
enum class TlsIo { Done, WantRead, WantWrite, Error };

// Process-wide client credentials and trust settings. One context is shared by
// every connection; sessions are per-socket.
//
// Deliberately no certificate *verification* by default: the tool's job is to
// exhaust a server's resources, and refusing to test a host because it presents
// a self-signed or expired certificate would block the common case of testing
// staging and appliance endpoints. Verification is opt-in via verify_peer.
class TlsContext {
 public:
  ~TlsContext();
  TlsContext(const TlsContext&) = delete;
  TlsContext& operator=(const TlsContext&) = delete;

  // Whether this build has a TLS backend compiled in at all.
  static bool available();

  // Builds a client context. Client certificates are loaded from the SSL_CERT
  // and SSL_KEY environment variables when both are set, matching the classic
  // tool's mTLS interface. Returns nullptr and sets `error` on failure.
  static std::shared_ptr<TlsContext> create(bool verify_peer, std::string& error);

  struct Impl;
  Impl* impl() const { return impl_.get(); }

 private:
  TlsContext();
  std::unique_ptr<Impl> impl_;
};

// One TLS connection, layered over an already-connected non-blocking socket fd.
// The fd stays owned by Socket; TlsSession never closes it.
class TlsSession {
 public:
  TlsSession();
  ~TlsSession();
  TlsSession(const TlsSession&) = delete;
  TlsSession& operator=(const TlsSession&) = delete;
  TlsSession(TlsSession&& other) noexcept;
  TlsSession& operator=(TlsSession&& other) noexcept;

  bool active() const;

  // Attaches to `fd` and sets SNI to `sni_host` (skipped when it is a literal IP
  // address, which SNI forbids). Does not start the handshake.
  bool attach(const std::shared_ptr<TlsContext>& ctx, int fd,
              const std::string& sni_host, std::string& error);

  // Drives the handshake one step. Call again on the requested readiness.
  TlsIo handshake();

  // Same contracts as Socket::send_some/recv_some, so the layer is transparent:
  //   send_some: bytes written (>= 0; 0 means would-block), -1 on fatal error
  //   recv_some: bytes read (> 0), 0 on clean peer shutdown, -1 would-block,
  //              -2 on fatal error
  long send_some(const char* data, std::size_t len);
  long recv_some(char* buf, std::size_t len);

  // e.g. "TLSv1.3 / TLS_AES_256_GCM_SHA384". Empty before the handshake finishes.
  std::string description() const;

  // Last OpenSSL error string, for diagnostics.
  const std::string& last_error() const;

  void reset();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_TLS_HPP_
