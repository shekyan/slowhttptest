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
 *  class SlowHTTPTest implements main functionality of slow HTTP attack
 *  vulnerability detection. before calling run_test(), class has to be initialized.
 *****/

#ifndef _SLOWHTTPTEST_H_
#define _SLOWHTTPTEST_H_

#include "netdb.h"
#include <string>
#include <vector>

#include "slowurl.h"

namespace slowhttptest {

enum SlowTestType {
  eHeader = 0,
  ePost
};

enum ExitStatusType {
  eTimeLimit = 0,
  eAllClosed,
  eHostNotAlive,
  eConnectionRefused
};

class SlowSocket;
class SlowHTTPTest {
 public:
  SlowHTTPTest(int delay, int duration, int interval, int con_cnt,
    int max_random_data_len, int content_length, SlowTestType type);
  ~SlowHTTPTest();

  bool init(const char* url);
  void report_parameters();
  void report_status();
  void report_final();
  bool run_test();

 private:
  void close_sock(int id);
  bool change_fd_limits();
  const char* get_random_extra();

  addrinfo* addr_;
  std::string request_;
  std::string random_extra_;
  std::string user_agent_;
  Url base_uri_;
  const char* separator_;
  const char* prefix_;
  const char* postfix_;
  std::vector<SlowSocket*> sock_;
  int delay_;
  int duration_;
  int followup_timing_;
  int followup_cnt_;
  int num_connections_;
  int extra_data_max_len_;
  int seconds_passed_;
  int content_length_;
  SlowTestType type_;
  int initializing_;
  int connecting_; 
  int connected_; 
  int errored_; 
  int closed_;


  ExitStatusType exit_status_;
};

}  // namespace slowhttptest
#endif
