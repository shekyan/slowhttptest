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
 *  http://code.google.com/p/slowhttptest/
 *
 *  class that parses URI and store URI components. 
 *****/

#ifndef _SLOWURL_H_
#define _SLOWURL_H_

#include <string>

namespace slowhttptest {

class Url {
 public:
  Url();
  bool prepare(const char* url);

  const int isSSL() const {
    return is_ssl_;
  }
  const std::string& getHost() const {
    return host_;
  }
  const int getPort() const {
    return port_;
  }
  const char* getPortStr() const {
    return port_str_.c_str();
  }
  const std::string& getPath() const {
    return path_;
  }
  const char* getData() const {
    return data_.c_str();
  }

  const size_t getPathLen() const {
    return path_.size();
  }

 private:
  std::string data_;
  std::string host_;
  std::string path_;
  std::string port_str_;
  int port_;
  bool is_ssl_;
};

class Proxy {
 public:
  Proxy();
  bool prepare(const char* proxy);
  const std::string& getHost() const {
    return host_;
  }
  const int getPort() const {
    return port_;
  }
  const char* getPortStr() const {
    return port_str_.c_str();
  }
  const char* getData() const {
    return data_.c_str();
  }

private:
  std::string data_;
  std::string host_;
  std::string port_str_;
  int port_;
 
};

} // namespace slowhttptest

#endif
