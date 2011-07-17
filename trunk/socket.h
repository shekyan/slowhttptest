// Wrappers around sockets.
//
// (c) Victor Agababov (vagababov@gmail.com) 2011
// Apache license goes here.


#ifndef _SLOW_HTTP_TEST_SOCKET_
#define _SLOW_HTTP_TEST_SOCKET_

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

namespace slowhttptest {

class Socket {
 public:
  static Socket* Create(const addrinfo* addr);
  virtual ~Socket();
  virtual int Send(const char* data, const int size);
  virtual int Recv(char* data, const int size);

 protected:
  virtual void Close();
  Socket();
  bool Init(const addrinfo* addr);
  int get_socket() const { return the_socket_; }

 private:
  int the_socket_;
};


}  // namespace slowhttptest

#endif  // _SLOW_HTTP_TEST_SOCKET_
