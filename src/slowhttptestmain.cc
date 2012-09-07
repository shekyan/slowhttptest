/*****************************************************************************
*  Copyright 2011 Sergey Shekyan, Victor Agababov
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
 *         Victor Agababov vagababov@gmail.com
 *
 * Slow HTTP attack vulnerability test tool
 *  http://code.google.com/p/slowhttptest/
 *****/

#include "config.h"
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <memory>
#include <cctype>

#include "slowlog.h"
#include "slowhttptest.h"

#define DEFAULT_URL "http://localhost/"

static void info() {
  printf("Try \'%s -h\' for more information\n", PACKAGE);
}
static void usage() {
  printf(
      "\n%s %s, a tool to test for slow HTTP "
      "DoS vulnerabilities.\n"
      "Usage:\n"
      "slowhttptest [-a <range start>] [-b <range limit>]\n"
      "[-c <number of connections>] [-<H|B|R|X>]\n"
      "[-d|e <proxy host:port>]\n"
      "[-g <generate statistics>]\n"
      "[-i <interval in seconds>] [-k <request multiply factor>]\n"
      "[-l <test duration in seconds>]\n"
      "[-n <slow read interval in seconds>] [-o <output file path and/or name>]\n"
      "[-p <timeout for probe connection>]\n"
      "[-r <connections per second>]\n"
      "[-s <value of Content-Length header>] [-t <verb>]\n"
      "[-u <URL>] [-v <verbosity level>] \n"
      "[-w <advertised window size range start>] [-x <max length of follow up data>]\n"
      "[-y <advertised window size range end>] [-z <slow read from recieve buffer in bytes>]\n"
      "Options:\n\t"
      "-a start,        left boundary of range in range header, default: 5\n\t"
      "-b bytes,        limit for range header right boundary values, default: 2000\n\t"
      "-c connections,  target number of connections, default: 50\n\t"
      "-d host:port,    all traffic directed through HTTP proxy at host:port, default: off\n\t"
      "-e host:port,    probe traffic directed through HTTP proxy at host:port, default: off\n\t"
      "-h               display this help and exit\n\t"
      "-H, -B, -R or X  specify test mode (slow headers,body, range or read),\n\t"
      "                 default: headers\n\t"
      "-g,              generate statistics with socket state changes,\n\t"
      "                 default: off\n\t"
      "-i seconds,      interval between followup data in seconds, default: 10\n\t"
      "-k num,          number of times to repeat same request in the connection\n\t"
      "                 Use to multiply response size if server supports persistent connections.\n\t"
      "                 Effective in slow read (-X) mode only, default: 1\n\t"
      "-l seconds,      target test length in seconds, default: 240\n\t"
      "-n seconds,      interval between read operations from recv buffer in seconds.\n\t"
      "                 Effective in slow read (-X) mode only, default: 1\n\t"
      "-o file,         save statistics output in file.html and file.csv,\n\t"
      "                 -g must be specified to use this option\n\t"
      "-p seconds,      timeout to wait for HTTP response on probe connection,\n\t"
      "                 after which server is considered inaccessible,\n\t"
      "                 default: 5\n\t"
      "-r num,          connection rate (connections per seconds), default: 50\n\t"
      "-s bytes,        value of Content-Length header if needed, default: 4096\n\t"
      "-t verb          verb to use in request,\n\t"
      "                 defalut to GET for slow headers and response and to POST for slow body\n\t"
      "-u URL,          absolute URL of target, default: http://localhost/\n\t"
      "-v level,        verbosity level 0-4: Fatal, Info, Error, Warning, Debug\n\t"
      "                 default: 1 - Info\n\t"
      "-w bytes,        start of the range advertised window size would be picked from.\n\t"
      "                 Effective in slow read (-X) mode only, min: 1, default: 1\n\t"
      "-x bytes,        max length of each randomized name/value pair of\n\t"
      "                 followup data per tick, e.g. -x 2 generates\n\t"
      "                 X-xx: xx for header or &xx=xx for body, where x\n\t"
      "                 is random character, default: 32\n\t"
      "-y bytes,        end of the range advertised window size would be picked from.\n\t"
      "                 Effective in slow read (-X) mode only, min: 1, default: 512\n\t"
      "-z bytes         bytes to slow read from receive buffer with single read() call.\n\t"
      "                 Effective in slow read (-X) mode only, default: 5\n"
      , PACKAGE
      , VERSION
      );
}

static bool check_window_range(int a,int b) {
  if(a > b) {
    printf("Error: start value of the advertised window range "
       "is higher (%d) than the end value (%d)\r\n", a, b);
    info();
    return  false;
  }
  return true;
}

static bool parse_int(int &val, long max = INT_MAX) {
  long tmp = strtol(optarg, 0, 10);
  if(tmp == 0) { //not last empty argument
    printf("Option -%c requires an argument.\n", optopt);
    info();
    return false;
  } else if(tmp < 0 || tmp > max) {
    printf("Error: invalid -%c value %ld, max: %ld\r\n",optopt, tmp, max);
    info();
    return false;
  } else {
    val = static_cast<int>(tmp);
    return true;
  }
}

// global flag to indicite if we need to run
int g_running = true;

void int_handler(int param) {
  g_running = false;  
}

using slowhttptest::slowlog_init;
using slowhttptest::slowlog;
using slowhttptest::SlowHTTPTest;
using slowhttptest::SlowTestType;
using slowhttptest::ProxyType;

int main(int argc, char **argv) {

  if (argc < 1) {
    info();
    return -1;
  }
  char url[1024] = { 0 };
  char path[1024] = { 0 };
  char proxy[1024] = { 0 };
  char verb[16] = { 0 };
  // default vaules
  int conn_cnt            = 50;
  int content_length      = 4096;
  int duration            = 240;
  int interval            = 10;
  int max_random_data_len = 32;
  int probe_interval      = 5;
  int range_start         = 5;
  int range_limit         = 2000;
  int rate                = 50;
  int read_interval       = 1;
  int read_len            = 5;
  int pipeline_factor     = 1;
  int debug_level         = LOG_INFO;
  bool  need_stats        = false;
  int window_upper_limit  = 512;
  int window_lower_limit  = 1;
  SlowTestType type = slowhttptest::eHeader;
  ProxyType proxy_type = slowhttptest::eNoProxy;
  long tmp;
  char o;
  while((o = getopt(argc, argv, ":HBRXgha:b:c:d:e:i:k:l:n:o:p:r:s:t:u:v:w:x:y:z:")) != -1) {
    switch (o) {
      case 'a':
        if(!parse_int(range_start, 65539))
          return -1;
        break;
      case 'b':
        if(!parse_int(range_limit, 524288))
          return -1;
        break;
      case 'c':
#ifdef HAVE_POLL
        if(!parse_int(conn_cnt, 65539))
#else
        if(!parse_int(conn_cnt, 1024))
#endif
          return -1;
        break;
      case 'd':
        strncpy(proxy, optarg, 1023);
        proxy_type = slowhttptest::eHTTPProxy;
        break;
      case 'e':
        strncpy(proxy, optarg, 1023);
        proxy_type = slowhttptest::eProbeProxy;
        break;
      case 'h':
        usage();
        return 1;
        break;
      case 'H':
        type = slowhttptest::eHeader;
        break;
      case 'B':
        type = slowhttptest::ePost;
        break;
      case 'R':
        type = slowhttptest::eRange;
        break;
      case 'X':
        type = slowhttptest::eSlowRead;
        break;
      case 'g':
        need_stats = true;
        break;
      case 'i':
        if(!parse_int(interval))
          return -1;
        break;
      case 'k':
        if(!parse_int(pipeline_factor, 10))
          return -1;
        break;
      case 'l':
        if(!parse_int(duration))
          return -1;
        break;
      case 'n':
        if(!parse_int(read_interval))
          return -1;
        break;
      case 'o':
        strncpy(path, optarg, 1023);
        break;
      case 'p':
        if(!parse_int(probe_interval))
          return -1;
        break;
      case 'r':
        if(!parse_int(rate))
          return -1;
        break;
      case 's':
        if(!parse_int(content_length))
          return -1;
        break;
      case 't':
        strncpy(verb, optarg, 15);
        break;
      case 'u':
        strncpy(url, optarg, 1023);
        break;
      case 'v':
        tmp = strtol(optarg, 0, 10);
        if(0 <= tmp && tmp <= 4) {
          debug_level = static_cast<int>(tmp);
        } else {
          debug_level = LOG_FATAL;
        }
        break;
      case 'w':
        if(!parse_int(window_lower_limit))
          return -1;
        break;
      case 'x':
        if(!parse_int(max_random_data_len))
          return -1;
        else
          if(max_random_data_len < 2) max_random_data_len = 2;
        break;
      case 'y':
        if(!parse_int(window_upper_limit))
          return -1;
        break;
      case 'z':
        if(!parse_int(read_len))
          return -1;
        break;
      case '?':
        printf("Illegal option -%c\n", optopt);
        info();
        return -1;
        break;
      default:
        printf("Option -%c requires an argument.\n", optopt);
        info();
        return -1;
    }
  }
  if(slowhttptest::eSlowRead == type 
      && !check_window_range(window_lower_limit, window_upper_limit))
    return -1;
  if(!strlen(url)) {
    strncpy(url, DEFAULT_URL, sizeof(DEFAULT_URL));
  }
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, &int_handler);
  slowlog_init(debug_level, NULL);
  std::auto_ptr<SlowHTTPTest> slow_test(
      new SlowHTTPTest(rate, duration, interval,
      conn_cnt, max_random_data_len, content_length,
      type, need_stats, pipeline_factor, probe_interval,
      range_start, range_limit, read_interval, read_len,
      window_lower_limit, window_upper_limit, proxy_type));
  if(!slow_test->init(url, verb, path, proxy)) {
    slowlog(LOG_FATAL, "%s: error setting up slow HTTP test\n", __FUNCTION__);
    return -1;
  } else if(!slow_test->run_test()) {
    slowlog(LOG_FATAL, "%s: error running slow HTTP test\n", __FUNCTION__);
    return -1;
  }
  slow_test->report_final();
  return 0;
}
