/*****************************************************************************
 * Licensed to Qualys, Inc. (QUALYS) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * QUALYS licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
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

#include <string>
#include <openssl/ssl.h>

struct hostent;
struct sockaddr_in;

namespace slowhttptest {
class Url;

enum SendType {
  eInitialSend = 0, eFollowUpSend
};

class SlowSocket {
public:
  SlowSocket();
  ~SlowSocket();
  // you should have a dtor, which calls close_slow, if it has not been closed yet.
  bool isEmpty() {
    return -1 == sockfd_ && !ssl_;
  }
  // Should all those methods be public?
  int close_slow();

  bool init(const hostent* server, const Url* url, int& maxfd,
      int followups_to_send);
  int recv_slow(void *buf, size_t len);
  int send_slow(const void *msg, size_t len, const SendType type =
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

private:

  int connect_plain(sockaddr_in & addr);
  int connect_ssl(sockaddr_in & addr);
  int set_nonblocking();
  // It is better to have each member have it's own type decl.
  int sockfd_;
  int requests_to_send_;
  int followups_to_send_;
  int offset_;
  SSL *ssl_;
  const void * buf_;
};

}  // namespace slowhttptest
#endif
