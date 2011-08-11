// Wrappers around sockets.
//
// (c) Victor Agababov (vagababov@gmail.com) 2011
// Apache license goes here.

#include "ssl_socket.h"
#include "slowlog.h"
#include <unistd.h>
#include <stdio.h>
#include <openssl/ssl.h>


namespace {
// This is a statically allocated class initializes SSL
// library and provides simple wrappers.
static class SSLContextHolder {
 public:
  SSLContextHolder() {
    // No reason to work without ssl
    if (1 != SSL_library_init()) {
      slowhttptest::check(false, "SSL Could not be initialized!");
    }
  }

  static SSL_CTX* CreateSSLContext() {
    SSL_METHOD* method = SSLv23_client_method();
    return SSL_CTX_new(method);
  }

  static SSL* CreateSSL(SSL_CTX* const context) {
    if (NULL == context) return NULL;
    return SSL_new(context);
  }
  
  static void ReleaseSSL(SSL* ssl, SSL_CTX* context) {
    if (NULL != ssl) {
      SSL_shutdown(ssl);
      SSL_free(ssl);
    }
    if (NULL != context) SSL_CTX_free(context);
  }
} ___ssl___;
}  // namespace


namespace slowhttptest {
SSLSocket::SSLSocket()
    : ssl_(0),
      context_(0) {
}

SSLSocket::~SSLSocket() {
  Close();
}

int SSLSocket::Send(const char* data, const int size) {
  CHECK_NOTNULL(data);
  return SSL_write(ssl_, data, size);
}

int SSLSocket::Recv(char* data, const int size) {
  CHECK_NOTNULL(data);
  return SSL_read(ssl_, data, size);
}

void SSLSocket::Close() {
  if (ssl_) {
    ___ssl___.ReleaseSSL(ssl_, context_);
    ssl_ = NULL;
    context_ = NULL;
  }
  Socket::Close();
}

bool SSLSocket::Init(const addrinfo* addr) {
  // Initialize underlying transport first.
  if (!Socket::Init(addr)) return false;

  // SSL ran out of memory or is not installed, no reason to go on.
  context_ = CHECK_NOTNULL(___ssl___.CreateSSLContext());
  ssl_ = CHECK_NOTNULL(___ssl___.CreateSSL(context_));
  SSL_set_fd(ssl_, get_socket());
  const int ret = SSL_connect(ssl_);
  if (ret != 1) {
    const int err = SSL_get_error(ssl_, ret);
    slowlog(LOG_ERROR, "%s: SSL connect error: %d\n", __FUNCTION__, err);
  }
  return ret == 1;
}

SSLSocket* SSLSocket::Create(const addrinfo* addr) {
  SSLSocket* sock = new SSLSocket();
  if (!sock->Init(addr)) {
    delete sock;
    sock = NULL;
  }
  return sock;
}

}  // namespace slowhttptest

