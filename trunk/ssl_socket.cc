

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
      printf("SSL Could not be initialized!");
      abort();
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
    if (NULL != ssl) SSL_free(ssl);
    if (NULL != context) SSL_CTX_free(context);
  }
} ___ssl___;
}  // namespace


namespace slowhttptest {
SSLSocket::SSLSocket()
    : fd_(-1),
      ssl_(0),
      context_(0) {
}

SSLSocket::~SSLSocket() {
  Close();
}

void SSLSocket::Close() {
  if (ssl_) {
    SSL_free(ssl_);
    ssl_ = NULL;
    SSL_CTX_free(context_);
    context_ = NULL;
  }
  if (fd_ > 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

bool SSLSocket::Init(int fd) {
  check(fd >= 0, "Invalid socket passed");
  // SSL ran out of memory, no reason to go on.
  context_ = CHECK_NOTNULL(___ssl___.CreateSSLContext());
  ssl_ = CHECK_NOTNULL(___ssl___.CreateSSL(context_));
  SSL_set_fd(ssl_, fd_);
  const int ret = SSL_connect(ssl_);
  if (ret != 1) {
    const int err = SSL_get_error(ssl_, ret);
    slowlog(0, "%s: SSL connect error: %d\n", __FUNCTION__, err);
    if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err) {
      Close();
    }
  }
  return ret == 1;
}

SSLSocket* SSLSocket::Create(int fd) {
  SSLSocket* sock = new SSLSocket();
  if (!sock->Init(fd)) {
    delete sock;
    sock = NULL;
  }
  return sock;
}

}  // slowhttptest
