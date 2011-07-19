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
 *****/

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <cmath>
#include <string>

#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "slowlog.h"
#include "slowsocket.h"
#include "slowurl.h"

namespace slowhttptest {
SlowSocket::SlowSocket()
    : sockfd_(-1), requests_to_send_(0),
      followups_to_send_(0), last_followup_timing_(0),
      offset_(0), ssl_(0), buf_(0) {
}

SlowSocket::~SlowSocket() {
  close();
}

int SlowSocket::set_nonblocking() {
  int flags;

  if(-1 == (flags = fcntl(sockfd_, F_GETFL, 0))) {
    flags = 0;
  }
  return fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);
}

bool SlowSocket::init(addrinfo* addr, const Url* url, int& maxfd,
                      int followups_to_send) {
  addrinfo* res;
  bool connected = false;
  for (res = addr; !connected && res; res = res->ai_next) {
    sockfd_ = socket(res->ai_family, res->ai_socktype,
     res->ai_protocol);
    if(-1 == sockfd_) {
      slowlog(LOG_ERROR, "%s: Failed to create socket\n", __FUNCTION__);
      return false;
    }

    if(-1 == set_nonblocking()) {
      slowlog(LOG_ERROR, "%s: Failed to set socket %d to non-blocking \n", __FUNCTION__,
       sockfd_);
      return false;
    }
    connected = url->isSSL() ? connect_ssl(addr) : connect_plain(addr); 
  }


  followups_to_send_ = followups_to_send;
  requests_to_send_ = 1;

  if(sockfd_ > maxfd) {
    maxfd = sockfd_;
  }
  return true;
}

bool SlowSocket::connect_plain(addrinfo* addr) {
  errno = 0;

  if (connect(sockfd_, addr->ai_addr, addr->ai_addrlen) < 0
      && EINPROGRESS != errno) {
    slowlog(LOG_ERROR, "%s: Cannot connect qsocket: %s %d \n", __FUNCTION__,
            strerror(errno), sockfd_);
    close();
    return false;
  }
  return true;
}

bool SlowSocket::connect_ssl(addrinfo* addr) {
  // Establish regular connection.
  if(!connect_plain(addr))  return false;
   
  // Init SSL related stuff.
  // TODO(vagababov): this is not thread safe of pretty.
  static bool ssl_is_initialized = false;
  if (!ssl_is_initialized) {
    SSL_library_init();
    ssl_is_initialized = true;
  }
  SSL_METHOD* method = NULL;
  SSL_CTX* ssl_ctx = NULL;
  method = SSLv23_client_method();
  ssl_ctx = SSL_CTX_new(method);
  if(!ssl_ctx) {
    slowlog(LOG_ERROR, "%s: Cannot create new SSL context\n", __FUNCTION__);
    close();
    return false;
  }
  ssl_ = SSL_new(ssl_ctx);
  if(!ssl_) {
    slowlog(LOG_ERROR, "%s: Cannot create SSL structure for a connection\n",
            __FUNCTION__);
    close();
    return false;
  }
  SSL_set_fd(ssl_, sockfd_);
  int ret = SSL_connect(ssl_);
  if(ret <= 0) {
    int err = SSL_get_error(ssl_, ret);
    slowlog(LOG_ERROR, "%s: SSL connect error: %d\n", __FUNCTION__, err);
    if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err) {
      close();
      return false;
    }
  }
  slowlog(LOG_DEBUG, "%s: SSL connection is using %s\n", __FUNCTION__,
          SSL_get_cipher(ssl_));
  return true;
}

int SlowSocket::recv_slow(void *buf, size_t len) {
  return ssl_ ? SSL_read(ssl_, buf, len)
              : recv(sockfd_, buf, len, 0);
}

int SlowSocket::send_slow(const void* buf, size_t len, const SendType type) {
  // VA: this is not good. create a "prepare" method.
  // initial send
  if(buf_ == 0) {
    buf_ = buf;
    offset_ = len;
  }

  int ret = ssl_ ? SSL_write(ssl_, buf_, offset_)
                 : send(sockfd_, buf_, offset_, 0);

  // entire data was sent
  if(ret > 0 && ret == offset_) {
    if(eInitialSend == type) {
      --requests_to_send_;
    } else if(eFollowUpSend == type) {
      --followups_to_send_;
    }
    buf_ = 0;
    offset_ = 0;
  } else if(ret > 0 && ret < offset_) {
    buf_ = static_cast<const char*>(buf_) + ret;
    offset_ -= ret;
  }  
  return ret;
}

void SlowSocket::close() {
  if (-1 == sockfd_) return;

  slowlog(LOG_DEBUG, "closing slow, sock is %d\n", sockfd_);
  if(ssl_) {
    SSL_free(ssl_);
    ssl_ = NULL;
  }
  requests_to_send_ = 0;
  followups_to_send_ = 0;
  ::close(sockfd_);
  sockfd_ = -1;
}

}  // namespace slowhttptest
