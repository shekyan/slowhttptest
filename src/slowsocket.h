/*****************************************************************************
*  Copyright 2011 Sergey Shekyan
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* *****************************************************************************/


/*****
 * Author: Sergey Shekyan sshekyan@qualys.com
 *
 * Slow HTTP attack  vulnerability test tool
 *  http://code.google.com/p/slowhttptest/
 *
 *  class SlowSocket is a wrapper around TCP socket structure.
 *  class gives unified access to main socket operations no matter 
 *  if it is plain or SSL connection.
 *****/

#ifndef _SLOWSOCKET_H_
#define _SLOWSOCKET_H_

#include <sys/time.h>

#include <string>
#include <openssl/ssl.h>

struct addrinfo;

namespace slowhttptest {
class Url;

enum SendType {
  eInitialSend = 0, eFollowUpSend
};

enum SocketState {
  eInit = 0, eError, eConnecting, eConnected, eClosed
};

class SlowSocket {
 public:
  SlowSocket();
  ~SlowSocket();
  bool isEmpty() {
    return -1 == sockfd_ && !ssl_;
  }
  const bool is_connect_initiated() const {return connect_initiated_;};
  void close();

  bool init(addrinfo* addr, const Url* url, int& maxfd,
      int followups_to_send);
  int recv_slow(void* buf, size_t len);
  int send_slow(const void* msg, size_t len, const SendType type =
      eInitialSend);
  const int get_sockfd() const {
    return sockfd_;
  }
  const int get_requests_to_send() const {
    return requests_to_send_;
  }
  const int get_followups_to_send() const {
    return followups_to_send_;
  }
  
  const int get_last_followup_timing() const {
    return last_followup_timing_;
  }

  void set_last_followup_timing(int timing) {
    last_followup_timing_ = timing;
  }

  void set_start(const timeval* t) {
    t_start_.tv_sec = t->tv_sec;
    t_start_.tv_usec = t->tv_usec;
  }

  const timeval& get_start() const {
    return t_start_ ;
  }

  void set_connected(const timeval* t) {
    t_connected_.tv_sec = t->tv_sec;
    t_connected_.tv_usec = t->tv_usec;
  }

  const timeval& get_connected() const {
    return t_connected_ ;
  }

  void set_stop(const timeval* t) {
    t_stop_.tv_sec = t->tv_sec;
    t_stop_.tv_usec = t->tv_usec;
  }

  const timeval& get_stop() const {
    return t_stop_ ;
  }

  void set_state(SocketState state) {
    state_ = state;
  }

  const SocketState& get_state() const {
    return state_;
  }

 private:
  bool connect_plain(addrinfo* addr);
  bool connect_ssl(addrinfo* addr);
  int set_nonblocking();
  
  int connect_initiated_;
  int sockfd_;
  int requests_to_send_;
  int followups_to_send_;
  int last_followup_timing_;
  int offset_;
  SSL* ssl_;
  const void* buf_;
  timeval t_start_;
  timeval t_connected_;
  timeval t_stop_;
  SocketState state_;
};

}  // namespace slowhttptest
#endif
