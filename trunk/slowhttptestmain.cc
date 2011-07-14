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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory>

#include "slowlog.h"
#include "slowhttptest.h"

static void usage() {
	printf(
			"Program that tests for slow HTTP DoS vulnerabilities.\n"
      "Usage:\n"
      "slowtest [-d debug] [-t header|body] [-u URL] "
      "[-c number of connections] [-i interval in sec] "
      "[-r connections per second] [-l test duration in sec]\n");
}

int main(int argc, char **argv) {

	if (argc < 2) {
		usage();
		return -1;
	}

	char url[1024] = { 0 };
	long tmp;
  bool debug = false;
	int conn_cnt = 100;
	int delay = 100;
	int interval = 10;
	int duration = 300;
	SlowTestType type = eHeader;
	char o;
	while((o = getopt(argc, argv, "t:l:c:i:r:u:d")) != -1) {
		switch (o) {
		case 'u':
			strncpy(url, optarg, 1024);
			break;
		case 'c':
			tmp = strtol(optarg, 0, 10);
			if(tmp && tmp <= INT_MAX) {
				conn_cnt = static_cast<int>(tmp);
      }
			else {
				return -1;
      }
      break;
    case 'd':
      debug = true; 
      break;
		case 't':
			if(!strcmp(optarg, "body")) {
				type = ePost;
      }
			break;
		case 'r':
			tmp = strtol(optarg, 0, 10);
			if(tmp && tmp <= INT_MAX) {
				delay = static_cast<int>(tmp);
      } else {
				return -1;
      }
			break;
		case 'i':
			tmp = strtol(optarg, 0, 10);
			if(tmp && tmp <= INT_MAX) {
				interval = static_cast<int>(tmp);
      } else {
				return -1;
      }
			break;
		case 'l':
			tmp = strtol(optarg, 0, 10);
			if(tmp && tmp <= INT_MAX) {
				duration = static_cast<int>(tmp);
      } else {
				return -1;
      }
			break;
    case '?':
     printf("Illegal option\n");
    usage();
    return -1;
		default:
			usage();
			return -1;
		}
	}
  log_init(debug);
	std::auto_ptr<SlowHTTPTest> slow_test(new SlowHTTPTest(delay, duration, interval, conn_cnt, type));
	if(!slow_test->init(url)) {
		printf("%s: ERROR setting up slow HTTP test\n", __FUNCTION__);
		return -1;
	} else if(!slow_test->run_test()) {
    return -1;
  }
  log_close();
	return 0;
}
