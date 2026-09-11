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

#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>

#include "slowurl.h"
#include <string>

namespace slowhttptest {
Url::Url()
    : port_(0),
      is_ssl_(false),
      is_literal_ipv6_(false) {
}

namespace {

// Case-insensitive prefix match for a URL scheme.
bool scheme_is(const std::string& url, const char* prefix) {
  const size_t n = strlen(prefix);
  if(url.size() < n) return false;
  for(size_t i = 0; i < n; ++i) {
    if(tolower(static_cast<unsigned char>(url[i])) !=
       tolower(static_cast<unsigned char>(prefix[i]))) {
      return false;
    }
  }
  return true;
}

}  // namespace

bool Url::prepare(const char* url) {
  // prepare() appends, so a second call on the same object concatenated the two
  // URLs: host came back as "first.examplefirst.example" and the path as the
  // rest of the second URL glued on. Nothing reuses a Url today -- both call
  // sites run once per run -- so this is a trap rather than a live bug, and it
  // costs nothing to close.
  data_.clear();
  host_.clear();
  path_.clear();
  port_str_.clear();
  port_ = 0;
  is_ssl_ = false;
  is_literal_ipv6_ = false;

  if(!url)
    return false;
  bool has_port = false;
  bool has_path = false;
  size_t host_len = 0;
  size_t path_start = 0;
  size_t port_start = 0;
  size_t tmp = 0;

  data_.append(url);
  const std::string scheme("https");
  size_t host_start = 0;

  // Match the scheme exactly, and case-insensitively (RFC 3986 3.1).
  //
  // The old test only required the string to start with "http" and to
  // have "://" at offset 4 or 5, so any five-character scheme passed --
  // httpx:// parsed happily. Worse, SSL was decided by data_[4] == 's',
  // lowercase only, so httpS:// was accepted *and* treated as cleartext:
  // a capital S in the scheme silently produced an unencrypted run.
  if(scheme_is(data_, "https://")) {
    is_ssl_ = true;
    host_start = 8;
  } else if(scheme_is(data_, "http://")) {
    is_ssl_ = false;
    host_start = 7;
  } else {
    return false;
  }
  if('[' == data_[host_start]) {
    size_t host_end = data_.find_first_of("]", host_start);
    if(host_end != std::string::npos) {
      host_len = host_end - host_start;
      tmp = data_.find_first_of(":", host_end);
      if(tmp != std::string::npos) {
        has_port = true;
        port_start = tmp;
      }
      tmp = host_start;
      is_literal_ipv6_ = true;
    } else {
      return false;
    }
  } else {
    tmp = data_.find_first_of(":", host_start);
    if(tmp != std::string::npos) {
      has_port = true;
      port_start = tmp;
    }
    tmp = host_start;
  }
  tmp = data_.find_first_of("/", tmp);
  if(tmp != std::string::npos) {
    has_path = true;
    path_start = tmp;
  }

  if(has_port)
    host_len = port_start;
  else if(has_path)
    host_len = path_start;
  else
    host_len = data_.size();
  // get host
  if(is_literal_ipv6_)
    host_.append(data_, host_start + 1, host_len - host_start - 2);
  else
    host_.append(data_, host_start, host_len - host_start);
 if(host_.size() == 0)
   return false;
  // get port
  if(has_port) {
    std::string port;
    if(has_path) {
      port.append(data_, port_start + 1, path_start - port_start - 1);

    } else {
      port.append(data_, port_start + 1, data_.size() - port_start - 1);
    }
    port_str_ = port;
    long tmp = strtol(port.c_str(), 0, 10);
    if(tmp && tmp <= USHRT_MAX) {
      port_ = static_cast<int>(tmp);
    } else
      return false;
  } else {
    port_ = is_ssl_ ? 443 : 80;
    port_str_ = is_ssl_?"443" : "80";
  }

  // get path
  if(has_path) {
    path_.append(data_, path_start, data_.size() - path_start);
  } else {
    path_.append("/");
    data_.append("/");
  }

  return true;
}

Proxy::Proxy()
    : port_(0) {
}

bool Proxy::prepare(const char* proxy) {
  // Same append-without-reset as Url::prepare.
  data_.clear();
  host_.clear();
  port_str_.clear();
  port_ = 0;

  if(!proxy)
    return false;
  data_.append(proxy);
  size_t delim = data_.find_first_of(':');
  if(delim == std::string::npos)
    return false;
  host_.append(data_, 0, delim);
  port_str_.append(data_, delim + 1, data_.size());
  long tmp = strtol(port_str_.c_str(), 0, 10);
  if(tmp && tmp <= USHRT_MAX) {
    port_ = static_cast<int>(tmp);
  } else {
    return false;
  }
  return true;
}




}  // namespace slowhttptest
