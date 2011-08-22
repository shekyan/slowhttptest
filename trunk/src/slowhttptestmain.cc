/*****************************************************************************
*  Copyright 2011 Sergey Shekya,n Victor Agababov
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
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <cctype>

#include "slowlog.h"
#include "slowhttptest.h"

#define DEFAULT_URL "http://localhost/"

static void usage() {
  printf(
      "\n%s v.%s, a tool to test for slow HTTP "
      "DoS vulnerabilities.\n"
      "Usage:\n"
      "slowtest [-c <number of connections>] [-<h|b>] [-g <generate statistics>]\n"
      "[-i <interval in seconds>] [-l <test duration in seconds>]\n"
      "-o <output file path and/or name>\n"
      "[-r <connections per second>]\n"
      "[-s <value of Content-Length header>] [-t <verb>]\n"
      "[-u <URL>]\n"
      "[-v <verbosity level>] [-x <max length of follow up data>]\n"
      "Options:\n\t"
      "-c connections,  target number of connections\n\t"
      "-h or -b,        specify test mode (slow headers or body)\n\t"
      "-g,              generate statistics with socket state changes\n\t"
      "-i seconds,      interval between followup data in seconds\n\t"
      "-l seconds,      target test length in seconds\n\t"
      "-o file,         place statistics output in file.html and file.csv\n\t"
      "-r num,          connection rate (connections per seconds)\n\t"
      "-s bytes,        value of Content-Length header for POST request\n\t"
      "-t verb          verb (defalut to GET for headers and POST for body)\n\t"
      "-u URL,          absolute URL to target, e.g http[s]://foo/bar\n\t"
      "-v level,        verbosity level 0-4: Fatal, Info, Error, Warning, Debug\n\t"
      "-x bytes,        max length of randomized followup data per tick\n"
      , PACKAGE
      , VERSION
      );
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

int main(int argc, char **argv) {

  if (argc < 1) {
    usage();
    return -1;
  }
  char url[1024] = { 0 };
  char path[1024] = { 0 };
  char verb[16] = { 0 };
  // default vaules
  int conn_cnt = 50;
  int content_length = 4096;
  int rate = 50;
  int duration = 240;
  int debug_level = LOG_INFO;
  int interval = 10;
  int max_random_data_len = 128;
  bool  need_stats = false;
  SlowTestType type = slowhttptest::eHeader;
  long tmp;
  char o;
  while((o = getopt(argc, argv, ":hbgc:i:l:o:r:s:t:u:v:x:")) != -1) {
    switch (o) {
      case 'c':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= 1024) {
          conn_cnt = static_cast<int>(tmp);
        } else {
          usage();
          return -1;
        }
        break;
      case 'h':
        type = slowhttptest::eHeader;
        break;
      case 'g':
        need_stats = true;
        break;
      case 'b':
        type = slowhttptest::ePost;
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
      case 'o':
        strncpy(path, optarg, 1023);
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
        } else {
          debug_level = LOG_FATAL;
        }
        break;
      case 'x':
        tmp = strtol(optarg, 0, 10);
        if(tmp && tmp <= INT_MAX) {
          max_random_data_len = static_cast<int>(tmp);
          if(max_random_data_len < 2) max_random_data_len = 2;
        } else {
          usage();
          return -1;
        }
        break;
      case '?':
        fprintf(stderr, "Illegal option -%c\n", optopt);
        usage();
        return -1;
        break;
      default:
        fprintf(stderr, "Option -%c requires an argument.\n", optopt);
        usage();
        return -1;
    }
  }
  if(!strlen(url)) {
    strncpy(url, DEFAULT_URL, sizeof(DEFAULT_URL));
  }
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, &int_handler);
  slowlog_init(debug_level, NULL);
  std::auto_ptr<SlowHTTPTest> slow_test(
    new SlowHTTPTest(rate, duration, interval, conn_cnt, 
    max_random_data_len, content_length, type, need_stats));
  if(!slow_test->init(url, verb, path)) {
    slowlog(LOG_FATAL, "%s: error setting up slow HTTP test\n", __FUNCTION__);
    return -1;
  } else if(!slow_test->run_test()) {
    slowlog(LOG_FATAL, "%s: error running slow HTTP test\n", __FUNCTION__);
    return -1;
  }
  slow_test->report_final();
  return 0;
}
