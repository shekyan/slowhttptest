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
 *  class SlowHTTPTest implements main functionality of slow HTTP attack
 *  vulnerability detection. before calling run_test(),
 *  class has to be initialized.
 *****/

#ifndef _SLOWHTTPTEST_H_
#define _SLOWHTTPTEST_H_

#include "netdb.h"
#include <string>
#include <vector>

#include "slowurl.h"
#include "text-generator.h"
namespace slowhttptest {

enum SlowTestType {
  eHeader = 0,
  ePost,
  eRange,
  eSlowRead
};

enum ExitStatusType {
  eTimeLimit = 0,
  eAllClosed,
  eHostNotAlive,
  eConnectionRefused,
  eCancelledByUser,
  eUnexpectedError
};

enum ProxyType {
  eHTTPProxy,
  eTunnelProxy,
  eSocks4Proxy,
  eSocks5Proxy,
  eProbeProxy,
  eNoProxy
};

class StatsDumper;
class RandomTextGenerator;
class SlowSocket;
class SlowHTTPTest {
 public:
  SlowHTTPTest(int delay, int duration, int interval,
   int con_cnt, int max_random_data_len, int content_length,
   SlowTestType type, bool need_stats,int pipeline_factor,
   int probe_interval, int range_start,
   int range_limit, int read_interval,
   int read_len, int window_lower_limit,
   int window_upper_limit, ProxyType proxy_type);
  ~SlowHTTPTest();

  bool init(const char* url, const char* verb,
    const char* path, const char* proxy);
  void report_parameters();
  void report_status(bool to_csv);
  void report_csv();
  void report_final();
  bool run_test();

 private:
  void close_sock(int id);
  bool change_fd_limits();
  const char* get_random_extra();
 
  static bool resolve_addr(const char* host, 
    const char* port, addrinfo **addr);
   
  RandomTextGenerator textgen_;
  addrinfo* addr_;
  addrinfo* probe_proxy_addr_;
  std::string request_;
  std::string probe_request_;
  std::string random_extra_;
  std::string verb_;
  std::string user_agent_;
  Url base_uri_;
  Proxy proxy_;
  const char* separator_;
  const char* prefix_;
  const char* postfix_;
  std::vector<SlowSocket*> sock_;
  SlowSocket* probe_socket_;
  int delay_;
  int duration_;
  int followup_timing_;
  int followup_cnt_;
  int num_connections_;
  int pipeline_factor_;
  int probe_timeout_;
  int extra_data_max_len_;
  int seconds_passed_;
  int content_length_;
  SlowTestType test_type_;
  bool need_stats_;
  int range_start_;
  int range_limit_;
  std::vector<StatsDumper*> dumpers_;
  ExitStatusType exit_status_;
  int initializing_;
  int connecting_; 
  int connected_; 
  int errored_; 
  int closed_;
  int extra_data_max_len_total_;
  int read_interval_;
  int read_len_;
  int window_lower_limit_;
  int window_upper_limit_;
  bool is_dosed_;
  ProxyType proxy_type_;
};

}  // namespace slowhttptest
#endif
