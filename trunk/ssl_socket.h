// Wrappers around sockets for work with SSL
//
// (c) Victor Agababov (vagababov@gmail.com) 2011
// Apache license goes here.


#ifndef _SLOW_HTTP_TEST_SSL_SOCKET_
#define _SLOW_HTTP_TEST_SSL_SOCKET_

#include <openssl/ssl.h>

namespace slowhttptest {
class SSLSocket {
 public:
  // Factory method to create a SSL Socket
  // Takes ownership of fd and will dispose of it.
  static SSLSocket* Create(int fd);
  ~SSLSocket();
 private:
  SSLSocket();
  bool Init(int fd); 
  void Close();

  int fd_;
  SSL* ssl_;   
  SSL_CTX* context_;
};

}  // slowhttptest
#endif // _SLOW_HTTP_TEST_SSL_SOCKET_
