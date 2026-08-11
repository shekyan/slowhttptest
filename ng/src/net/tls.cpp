// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
//
// OpenSSL-backed implementation of the TlsBackend interface. The whole file is
// conditional: with SLOWHTTP_HAVE_TLS undefined it still compiles and every
// entry point reports "not available", so a build without libssl loses https
// rather than failing to link.
#include "slowhttp/tls.hpp"

#include <cstring>
#include <string>

#ifdef SLOWHTTP_HAVE_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <cstdlib>
#endif

namespace slowhttp {

#ifdef SLOWHTTP_HAVE_TLS

namespace {

std::string openssl_error() {
  std::string out;
  unsigned long e;
  while ((e = ERR_get_error()) != 0) {
    char buf[256];
    ERR_error_string_n(e, buf, sizeof(buf));
    if (!out.empty()) out += "; ";
    out += buf;
  }
  return out.empty() ? "unknown TLS error" : out;
}

// SNI must carry a DNS name, never an IP literal (RFC 6066 §3). Sending one is a
// protocol violation that some servers reject outright, so detect and skip.
bool looks_like_ip(const std::string& host) {
  if (host.find(':') != std::string::npos) return true;  // IPv6 literal
  int dots = 0;
  for (char c : host) {
    if (c == '.') {
      ++dots;
    } else if (c < '0' || c > '9') {
      return false;
    }
  }
  return dots == 3;
}

}  // namespace

struct TlsContext::Impl {
  SSL_CTX* ctx = nullptr;
  ~Impl() {
    if (ctx) SSL_CTX_free(ctx);
  }
};

TlsContext::TlsContext() : impl_(new Impl) {}
TlsContext::~TlsContext() = default;

bool TlsContext::available() { return true; }

std::shared_ptr<TlsContext> TlsContext::create(bool verify_peer,
                                               std::string& error) {
  std::shared_ptr<TlsContext> self(new TlsContext);
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    error = "SSL_CTX_new failed: " + openssl_error();
    return nullptr;
  }
  self->impl_->ctx = ctx;

  // TLS 1.2 floor: below that the ciphers are broken, and any server we could
  // meaningfully load-test supports at least 1.2.
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE |
                            SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  if (verify_peer) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
      error = "cannot load system trust store: " + openssl_error();
      return nullptr;
    }
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  }

  // Client certificates, from the same environment variables the classic tool
  // uses so existing mTLS setups keep working unchanged.
  const char* cert = std::getenv("SSL_CERT");
  const char* key = std::getenv("SSL_KEY");
  if (cert && key && *cert && *key) {
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
      error = std::string("cannot load client certificate from SSL_CERT=") +
              cert + ": " + openssl_error();
      return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
      error = std::string("cannot load private key from SSL_KEY=") + key + ": " +
              openssl_error();
      return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
      error = "client certificate and private key do not match: " +
              openssl_error();
      return nullptr;
    }
  } else if ((cert && *cert) || (key && *key)) {
    // Half a client identity is almost certainly a mistake, and silently
    // proceeding without it would produce a confusing 400 from the server.
    error = "SSL_CERT and SSL_KEY must be set together for client certificates";
    return nullptr;
  }
  return self;
}

struct TlsSession::Impl {
  SSL* ssl = nullptr;
  std::string error;
  bool handshake_done = false;

  ~Impl() {
    if (ssl) SSL_free(ssl);
  }
};

TlsSession::TlsSession() : impl_(new Impl) {}
TlsSession::~TlsSession() = default;
TlsSession::TlsSession(TlsSession&& other) noexcept
    : impl_(std::move(other.impl_)) {}
TlsSession& TlsSession::operator=(TlsSession&& other) noexcept {
  if (this != &other) impl_ = std::move(other.impl_);
  return *this;
}

bool TlsSession::active() const { return impl_ && impl_->ssl != nullptr; }

bool TlsSession::attach(const std::shared_ptr<TlsContext>& ctx, int fd,
                        const std::string& sni_host, std::string& error) {
  if (!ctx || !ctx->impl() || !ctx->impl()->ctx) {
    error = "no TLS context";
    return false;
  }
  reset();
  impl_->ssl = SSL_new(ctx->impl()->ctx);
  if (!impl_->ssl) {
    error = "SSL_new failed: " + openssl_error();
    return false;
  }
  if (SSL_set_fd(impl_->ssl, fd) != 1) {
    error = "SSL_set_fd failed: " + openssl_error();
    reset();
    return false;
  }
  if (!sni_host.empty() && !looks_like_ip(sni_host)) {
    SSL_set_tlsext_host_name(impl_->ssl, sni_host.c_str());
    // Only meaningful when verification is on; harmless otherwise.
    SSL_set1_host(impl_->ssl, sni_host.c_str());
  }
  SSL_set_connect_state(impl_->ssl);
  return true;
}

TlsIo TlsSession::handshake() {
  if (!impl_ || !impl_->ssl) {
    if (impl_) impl_->error = "handshake on a detached session";
    return TlsIo::Error;
  }
  if (impl_->handshake_done) return TlsIo::Done;
  ERR_clear_error();
  int rc = SSL_do_handshake(impl_->ssl);
  if (rc == 1) {
    impl_->handshake_done = true;
    return TlsIo::Done;
  }
  switch (SSL_get_error(impl_->ssl, rc)) {
    case SSL_ERROR_WANT_READ:  return TlsIo::WantRead;
    case SSL_ERROR_WANT_WRITE: return TlsIo::WantWrite;
    default:
      impl_->error = openssl_error();
      return TlsIo::Error;
  }
}

long TlsSession::send_some(const char* data, std::size_t len) {
  if (!impl_ || !impl_->ssl) return -1;
  if (len == 0) return 0;
  ERR_clear_error();
  int n = SSL_write(impl_->ssl, data, static_cast<int>(len));
  if (n > 0) return n;
  switch (SSL_get_error(impl_->ssl, n)) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return 0;  // would block; retry on the next writable event
    default:
      impl_->error = openssl_error();
      return -1;
  }
}

long TlsSession::recv_some(char* buf, std::size_t len) {
  if (!impl_ || !impl_->ssl) return -2;
  if (len == 0) return -1;
  ERR_clear_error();
  int n = SSL_read(impl_->ssl, buf, static_cast<int>(len));
  if (n > 0) return n;
  switch (SSL_get_error(impl_->ssl, n)) {
    case SSL_ERROR_ZERO_RETURN:
      return 0;  // peer sent close_notify
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      return -1;
    case SSL_ERROR_SYSCALL:
      // A truncated connection: the peer vanished without close_notify. For this
      // tool that is indistinguishable from EOF and is what most servers do when
      // they reap a slow client, so report it as a clean end rather than an error.
      return 0;
    default:
      impl_->error = openssl_error();
      return -2;
  }
}

std::string TlsSession::description() const {
  if (!impl_ || !impl_->ssl || !impl_->handshake_done) return {};
  const char* ver = SSL_get_version(impl_->ssl);
  const SSL_CIPHER* c = SSL_get_current_cipher(impl_->ssl);
  std::string out = ver ? ver : "TLS";
  if (c) {
    out += " / ";
    out += SSL_CIPHER_get_name(c);
  }
  return out;
}

const std::string& TlsSession::last_error() const {
  static const std::string kEmpty;
  return impl_ ? impl_->error : kEmpty;
}

void TlsSession::reset() {
  if (!impl_) return;
  if (impl_->ssl) {
    SSL_free(impl_->ssl);
    impl_->ssl = nullptr;
  }
  impl_->handshake_done = false;
}

#else  // !SLOWHTTP_HAVE_TLS

// Stubs for builds configured with -DSLOWHTTP_TLS=OFF. Everything links; https
// is refused with an explanation at startup instead of failing at compile time.

struct TlsContext::Impl {};
TlsContext::TlsContext() : impl_(new Impl) {}
TlsContext::~TlsContext() = default;

bool TlsContext::available() { return false; }

std::shared_ptr<TlsContext> TlsContext::create(bool /*verify_peer*/,
                                               std::string& error) {
  error = "this build has no TLS backend (configured with -DSLOWHTTP_TLS=OFF)";
  return nullptr;
}

struct TlsSession::Impl {
  std::string error = "no TLS backend in this build";
};

TlsSession::TlsSession() : impl_(new Impl) {}
TlsSession::~TlsSession() = default;
TlsSession::TlsSession(TlsSession&& other) noexcept
    : impl_(std::move(other.impl_)) {}
TlsSession& TlsSession::operator=(TlsSession&& other) noexcept {
  if (this != &other) impl_ = std::move(other.impl_);
  return *this;
}

bool TlsSession::active() const { return false; }
bool TlsSession::attach(const std::shared_ptr<TlsContext>&, int,
                        const std::string&, std::string& error) {
  error = "no TLS backend in this build";
  return false;
}
TlsIo TlsSession::handshake() { return TlsIo::Error; }
long TlsSession::send_some(const char*, std::size_t) { return -1; }
long TlsSession::recv_some(char*, std::size_t) { return -2; }
std::string TlsSession::description() const { return {}; }
const std::string& TlsSession::last_error() const { return impl_->error; }
void TlsSession::reset() {}

#endif  // SLOWHTTP_HAVE_TLS

}  // namespace slowhttp
