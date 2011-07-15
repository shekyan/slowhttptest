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

SlowSocket::SlowSocket() :
		sockfd_(-1), requests_to_send_(0), followups_to_send_(0), offset_(0), ssl_(
				0), buf_(0) {

}

SlowSocket::~SlowSocket() {

	//printf("%s: DTOR\n", __FUNCTION__);
	close_slow();
}
int SlowSocket::set_nonblocking() {
	int flags;

	if(-1 == (flags = fcntl(sockfd_, F_GETFL, 0))) {
		flags = 0;
	}
	return fcntl(sockfd_, F_SETFL, flags | O_NONBLOCK);
}

bool SlowSocket::init(hostent* server, const Url* url, int& maxfd,
		int followups_to_send) {

	sockaddr_in addr;
	memset((void*) &addr, '\0', sizeof(addr));
	addr.sin_family = AF_INET;

	memcpy((char *) &addr.sin_addr.s_addr, (char *) server->h_addr,
			server->h_length);

	addr.sin_port = htons(url->getPort());
	followups_to_send_ = followups_to_send;
	requests_to_send_ = 1;
	sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == sockfd_) {
		slowlog(0, "%s: Failed to create socket\n", __FUNCTION__);
		return false;
	}
	if(-1 == set_nonblocking()) {
		slowlog(0, "%s: Failed to set socket %d to non-blocking \n", __FUNCTION__,
				sockfd_);
		return false;
	}

	if(url->isSSL()) {
		sockfd_ = connect_ssl(addr);
	} else {
		sockfd_ = connect_plain(addr);
	}

	if(sockfd_ > maxfd) {
		maxfd = sockfd_;
	}

	return true;
}

int SlowSocket::connect_plain(sockaddr_in & addr) {
	errno = 0;
	if(sockfd_ > 0 && connect(sockfd_, (sockaddr*) &addr, sizeof(addr)) < 0) {
		if(EINPROGRESS != errno) {
			slowlog(1, "%s: Cannot connect qsocket: %s %d \n", __FUNCTION__,
					strerror(errno), sockfd_);
			close(sockfd_);
			return -1;
		}
	}
	return sockfd_;
}

int SlowSocket::connect_ssl(sockaddr_in & addr) {
	if(!connect_plain(addr)) {
		return sockfd_; // return -1?
	}

	SSL_library_init();
	SSL_METHOD *method = NULL;
	SSL_CTX *ssl_ctx = NULL;
	method = SSLv23_client_method();
	ssl_ctx = SSL_CTX_new(method);
	if(!ssl_ctx) {
	  slowlog(0, "%s: Cannot create new SSL context\n", __FUNCTION__);
		close_slow();
		return sockfd_; // Is it usable? may be -1?
	}
	ssl_ = SSL_new(ssl_ctx);
	if(!ssl_) {
		slowlog(0, "%s: Cannot create SSL structure for a connection\n",
				__FUNCTION__);
		close_slow();
		return sockfd_; // same.
	}
	SSL_set_fd(ssl_, sockfd_);
	int ret = SSL_connect(ssl_);
	if(ret <= 0) {
		int err = SSL_get_error(ssl_, ret);
		slowlog(0, "%s: SSL connect error: %d\n", __FUNCTION__, err);
		if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err) {
			close_slow();
			return sockfd_; // same
		}
	}
	slowlog(5, "%s: SSL connection is using %s\n", __FUNCTION__,
			SSL_get_cipher(ssl_));
	return sockfd_;
}

int SlowSocket::recv_slow(void *buf, size_t len) {
	if(ssl_) {
		return SSL_read(ssl_, buf, len);
	} else {
		return recv(sockfd_, buf, len, 0);
	}
}

int SlowSocket::send_slow(const void *buf, size_t len, const SendType type) {

	// VA: this is not good. create a "prepare" method.
	// initial send
	if(buf_ == 0) {
		buf_ = buf;
		offset_ = len;
	}

	int ret;
	if(ssl_) {
		ret = SSL_write(ssl_, buf_, offset_);
	} else {
		ret = send(sockfd_, buf_, offset_, 0);
	}
	// entire data was sent

	if(ret > 0 && ret == offset_) {
		if(eInitialSend == type)
			requests_to_send_--;
		else if(eFollowUpSend == type)
			followups_to_send_--;
		buf_ = 0;
		offset_ = 0;
	} else if(ret > 0 && ret < offset_) {
		buf_ = static_cast<const char*>(buf_) + ret;
		offset_ = offset_ - ret;
	}
	return ret;
}
int SlowSocket::close_slow() {
	slowlog(7, "closing slow, sock is %d\n", sockfd_);
	int ret = -1;
	if(ssl_) {
		SSL_free(ssl_);
		ssl_ = NULL;
	}
	requests_to_send_ = 0;
	followups_to_send_ = 0;
	if(sockfd_ > 0) {
		ret = close(sockfd_);
	}
	sockfd_ = -1;
	return ret;
}
