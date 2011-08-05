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
 * Slow HTTP attack vulnerability test tool
 *  http://code.google.com/p/slowhttptest/
 *****/
#include "config.h"
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <cctype>

#include "slowlog.h"
#include "slowhttptest.h"

static void usage() {
  printf(
      "%s v.%s, a tool to test for slow HTTP "
      "DoS vulnerabilities.\n"
      "Usage:\n"
      "slowtest [-c <number of connections>] [-<h|b>]\n"
      "[-i <interval in seconds>] [-l <test duration in seconds>]\n"
      "[-r <connections per second>] [-u <URL>]\n"
      "[-s <value of Content-Length header>] [-t <verb>]\n"
      "[-v <verbosity level>] [-x <max length of follow up data>]\n"
      "Options:\n\t"
      "-c,        target number of connections\n\t"
      "-h or -b,  specifies test mode (slow down either headers or body)\n\t"
      "-i,        interval between followup data in seconds\n\t"
      "-l,        target test length in seconds\n\t"
      "-r,        connection rate (connections per seconds)\n\t"
      "-s,        value of Content-Length header for POST request\n\t"
      "-t         verb to use (defalut to GET for headers and POST for body)\n\t"
      "-u,        absolute URL to target, e.g http(s)://foo/bar\n\t"
      "-v,        verbosity level 0-4: Fatal, Info, Error, Warning, Debug\n\t"
      "-x,        max length of randomized followup data per tick\n"
      , PACKAGE
      , VERSION
      );
}


using slowhttptest::slowlog_init;
using slowhttptest::slowlog;
using slowhttptest::SlowHTTPTest;
using slowhttptest::SlowTestType;

int main(int argc, char **argv) {

  if (argc < 3) {
    usage();
    return -1;
  }
  char url[1024] = { 0 };
  char verb[16] = { 0 };
  // default vaules
  int conn_cnt = 50;
  int rate = 50;
  int duration = 240;
  int interval = 10;
  int debug_level = LOG_INFO;
  int max_random_data_len = 128;
  int content_length = 4096;
  SlowTestType type = slowhttptest::eHeader;
  long tmp;
  char o;
  while((o = getopt(argc, argv, ":hbc:i:l:r:s:t:u:v:x:")) != -1) {
    switch (o) {
      case 'c':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= 1024) {
          conn_cnt = static_cast<int>(tmp);
        }
        else {
          usage();
          return -1;
        }
        break;
      case 'h':
        type = slowhttptest::eHeader;
        break;
      case 'i':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= INT_MAX) {
          interval = static_cast<int>(tmp);
        } else {
          usage();
          return -1;
        }
        break;
      case 'l':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= INT_MAX) {
          duration = static_cast<int>(tmp);
        } else {
          usage();
          return -1;
        }
        break;
      case 'b':
        type = slowhttptest::ePost;
        break;
      case 'r':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= INT_MAX) {
          rate = static_cast<int>(tmp);
        } else {
          usage();
          return -1;
        }
        break;
      case 's':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= INT_MAX) {
          content_length = static_cast<int>(tmp);
        } else {
          usage();
          return -1;
        }
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
        }
        else {
          debug_level = LOG_FATAL;
        }
        break;
      case 'x':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= INT_MAX) {
          max_random_data_len = static_cast<int>(tmp);
        } else {
          usage();
          return -1;
        }
        break;
      case '?':
        printf("Illegal option\n");
        usage();
        return -1;
        break;
      default:
        usage();
        return -1;
    }
  }
  signal(SIGPIPE, SIG_IGN);
  slowlog_init(debug_level, NULL);
  std::auto_ptr<SlowHTTPTest> slow_test(
    new SlowHTTPTest(rate, duration, interval, conn_cnt, 
    max_random_data_len, content_length, type));
  if(!slow_test->init(url, verb)) {
    slowlog(LOG_FATAL, "%s: error setting up slow HTTP test\n", __FUNCTION__);
    return -1;
  } else if(!slow_test->run_test()) {
    slowlog(LOG_FATAL, "%s: error running slow HTTP test\n", __FUNCTION__);
    return -1;
  }
  slow_test->report_final();
  return 0;
}
