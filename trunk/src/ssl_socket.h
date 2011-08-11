// Wrappers around sockets for work with SSL
//
// (c) Victor Agababov (vagababov@gmail.com) 2011
// Apache license goes here.

#ifndef _SLOW_HTTP_TEST_SSL_SOCKET_
#define _SLOW_HTTP_TEST_SSL_SOCKET_

#include "socket.h"
#include <openssl/ssl.h>
#include <netdb.h>

namespace slowhttptest {
// This is a simple wrapper around SSL wrapped sockets.
// The instances of the class are created using factory method
// Create on the heap. Instances are initialized using addrinfo structure.
class SSLSocket : public Socket {
 public:
  // Factory method to create a SSL Socket
  // Will return NULL if initialization of the socket fails.
  static SSLSocket* Create(const addrinfo* addr);
  virtual ~SSLSocket();

  int Send(const char* data, const int size);
  int Recv(char* data, const int size);

 protected:
  virtual bool Init(const addrinfo* addr); 
  virtual void Close();

 private:
  // No derivations of this class are expected.
  SSLSocket();

  SSL* ssl_;   
  SSL_CTX* context_;
};

}  // namespace slowhttptest
#endif // _SLOW_HTTP_TEST_SSL_SOCKET_
