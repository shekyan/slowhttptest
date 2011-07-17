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
// This class is a simple wrapper around BSD Sockets.
// It works as factory producing instances of the Socket class
// on the heap. The instances are initialized with the addrinfo structure.
class Socket {
 public:
  // Creates and intializes socket wrapper with given addrinfo structure.
  // Will return NULL if the initialization of the socket fails.
  static Socket* Create(const addrinfo* addr);
  virtual ~Socket();

  // Sends size bytes from data. Will return how bytes have been
  // actually sent.
  virtual int Send(const char* data, const int size);
  
  // Receives at most size byes in the data buffer.
  // Returns how many byts have actually been received.
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
