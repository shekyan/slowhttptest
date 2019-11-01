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
 * Author: Sergey Shekyan shekyan@gmail.com
 *
 * Slow HTTP attack  vulnerability test tool
 *  https://github.com/shekyan/slowhttptest
 *****/

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include <openssl/ssl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "slowlog.h"
#include "slowsocket.h"
#include "slowurl.h"

namespace slowhttptest {
SlowSocket::SlowSocket()
    : sockfd_(-1),
      requests_to_send_(0),
      followups_to_send_(0),
      last_followup_timing_(0),
      offset_(0),
      ssl_(0),
      ssl_ctx_(0),
      buf_(0),
      start_in_millisecs_(0),
      connected_in_millisecs_(0),
      stop_in_millisecs_(0),
      state_(eInit),
      last_read_in_msec_(0),
      window_size_(-1),
      read_interval_(0){
}

SlowSocket::~SlowSocket() {
  close();
}

bool SlowSocket::set_window_size(int wnd_size) {
  int actual_wnd_size = 0;
  socklen_t actual_wnd_size_len = sizeof(actual_wnd_size);
	bool ret = setsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, &wnd_size, sizeof(wnd_size));
  if(ret) {
    slowlog(LOG_ERROR, "error setting socket send buffer size to %d: %s\n", wnd_size, strerror(errno));
  } else {
    getsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, &actual_wnd_size, &actual_wnd_size_len);
    slowlog(LOG_DEBUG, "set socket %d receive buffer size to %d bytes(requested %d)\n", sockfd_, actual_wnd_size, wnd_size);
  }
  return ret; 
}

int SlowSocket::set_nonblocking() {
  int flags;

  if(-1 == (flags = fcntl(sockfd_, F_GETFL, 0))) {
    flags = 0;
  }
  return fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);
}

bool SlowSocket::init(addrinfo* addr, const bool isSSL, int& maxfd,
                      int followups_to_send, int read_interval,
                      int wnd_lower_limit, int wnd_upper_limit) {
 	read_interval_ = read_interval * 1000;
  if(read_interval_) { // slow read test
    if(wnd_upper_limit == wnd_lower_limit) {
      window_size_ = wnd_upper_limit;
    } else {
      window_size_ = rand() % (wnd_upper_limit - wnd_lower_limit) + wnd_lower_limit;
      // if(!window_size_) // null is not a good choice
      // window_size_ = 1; 
    }
  }
	addrinfo* res;
  bool connect_initiated = false;
  bool addr_found = false;
  for (res = addr; !connect_initiated && res; res = res->ai_next) {
    addr_found = true;
    sockfd_ = socket(res->ai_family, res->ai_socktype,
                     res->ai_protocol);
    if(-1 == sockfd_) {
      slowlog(LOG_ERROR, "failed to create socket: %s\n", strerror(errno));
      return false;
    }

    if(-1 == set_nonblocking()) {
      slowlog(LOG_ERROR, "failed to set socket %d to non-blocking \n", sockfd_);
      return false;
    }
    if(read_interval_) {
      set_window_size(window_size_);
    }
    slowlog(LOG_DEBUG, "socket %d created \n", sockfd_);
    if((connect_initiated = isSSL ? connect_ssl(addr) : connect_plain(addr))) {
      break; // found right addrinfo
    }
  }
  if(!addr_found) {
    slowlog(LOG_FATAL, "addrinfo corrupted/null\n");
    return false;
  }
  followups_to_send_ = followups_to_send;
  requests_to_send_ = 1;

  maxfd = std::max(sockfd_, maxfd);
  return true;
}

bool SlowSocket::connect_plain(addrinfo* addr) {
  errno = 0;

  if (connect(sockfd_, addr->ai_addr, addr->ai_addrlen) < 0
      && EINPROGRESS != errno) {
    slowlog(LOG_ERROR, "cannot connect socket %d: %s\n", sockfd_,
            strerror(errno));
    close();
    return false;
  }
  return true;
}

bool SlowSocket::connect_ssl(addrinfo* addr) {
  // Establish regular connection.
  if(!connect_plain(addr)) return false;
   
  // Init SSL related stuff.
  static bool ssl_is_initialized = false;
  if (!ssl_is_initialized) {
    SSL_library_init();
    ssl_is_initialized = true;
  }
  SSL_METHOD* method = NULL;
  method = (SSL_METHOD*)SSLv23_client_method();
  ssl_ctx_ = SSL_CTX_new(method);
  if(!ssl_ctx_) {
    slowlog(LOG_ERROR, "cannot create new SSL context\n");
    close();
    return false;
  }
  ssl_ = SSL_new(ssl_ctx_);
  if(!ssl_) {
    SSL_CTX_free(ssl_ctx_);
    slowlog(LOG_ERROR, "cannot create SSL structure for a connection\n");
    close();
    return false;
  }
  SSL_set_fd(ssl_, sockfd_);
  int ret = SSL_connect(ssl_);
  if(ret <= 0) {
    int err = SSL_get_error(ssl_, ret);
    //slowlog(LOG_ERROR, "socket %d: SSL connect error: %d\n", sockfd_, err);
    if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err) {
      close();
      return false;
    }
  }
  return true;
}

int SlowSocket::recv_slow(void* buf, size_t len) {
  int ret = ssl_ ? SSL_read(ssl_, buf, len)
                 : recv(sockfd_, buf, len, 0);
  if(ssl_) {
    if(ret < 0) { 
      int err = SSL_get_error(ssl_, ret);
      if(err == SSL_ERROR_WANT_WRITE) {
        requests_to_send_ = 1;
      }
    } 
    if(SSL_is_init_finished(ssl_) && (state_ == eConnecting)) {
      requests_to_send_ = 1;
    }
  } 
  return ret;
}

int SlowSocket::send_slow(const void* buf, size_t len, const SendType type) {
  int ret;
  if(ssl_) {
    if(!SSL_is_init_finished(ssl_)) {
      ret = SSL_do_handshake(ssl_);
      if(ret <= 0) {
        int err = SSL_get_error(ssl_, ret);
        if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err) {
          slowlog(LOG_ERROR, "socket %d: SSL connect error: %d\n", sockfd_, err);
          close();
          return -1;
        } else {
          if(SSL_ERROR_WANT_READ == err) {
            requests_to_send_ = 0;
          }
          else {
            requests_to_send_ = 1;
          }
          errno = EAGAIN;
          return -1;
        }
      } else { //connected and handhsake finished
        requests_to_send_ = 1;
      }
    } else {
      if(requests_to_send_ > 0) { //report for initial data only
        slowlog(LOG_DEBUG, "socket %d: SSL connection is using %s\n", sockfd_,
            SSL_get_cipher(ssl_));
      }
    }
  }
  // VA: this is not good. create a "prepare" method.
  // initial send
  if(buf_ == 0) {
    buf_ = buf;
    offset_ = len;
  }

  ret = ssl_ ? SSL_write(ssl_, buf_, offset_)
                 : send(sockfd_, buf_, offset_, 0);

  // entire data was sent
  if(ret > 0 && ret == offset_) {
    if(eInitialSend == type) {
      requests_to_send_ = 0;
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

  slowlog(LOG_DEBUG, "closing slow socket %d\n", sockfd_);
  if(ssl_) {
    SSL_free(ssl_);
    SSL_CTX_free(ssl_ctx_);
    ssl_ = NULL;
    ssl_ctx_ = NULL;
  }
  requests_to_send_ = 0;
  followups_to_send_ = 0;
  ::close(sockfd_);
  sockfd_ = -1;
}

void SlowSocket::set_state(SocketState state) {
  timeval t;
  gettimeofday(&t, 0);
  switch(state) {
    case eInit:
      break;
    case eConnecting:
      set_start(&t);
      break;
    case eConnected:
      set_connected(&t);
      break;
    case eError:
      break;
    case eClosed:
      set_stop(&t);
      break;
    default:
      break;
  } 
  state_ = state;
}

void SlowSocket::set_last_read(const timeval* t) {
  if(read_interval_) {
    last_read_in_msec_ = timeval_to_milliseconds(t);
  }
}

const bool SlowSocket::is_ready_read(const timeval* t) const {
  if(!read_interval_) //don't bother doing anything
    return true;
  long now = timeval_to_milliseconds(t);
  if(last_read_in_msec_ == 0) {
    now = read_interval_ + 1;
  }
  if(now - last_read_in_msec_ > read_interval_) {
    return true;
  } else {
    return false;
  }
}



}  // namespace slowhttptest
