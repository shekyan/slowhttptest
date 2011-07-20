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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctime>
#include <string.h>
#include <execinfo.h>

#include "slowlog.h"

namespace {
static FILE* log_file = NULL;
int current_log_level;

void dispose_of_log() {
  if (log_file != stdout) {
    fclose(log_file);
  }
}


void print_call_stack() {
  static void* buf[64];
  const int depth = backtrace(buf, sizeof(buf)/sizeof(buf[0]));
  backtrace_symbols_fd(buf, depth, fileno(stdout));
  if (stdout != log_file) {
    backtrace_symbols_fd(buf, depth, fileno(log_file));
  }
}
}

namespace slowhttptest {
void slowlog_init(int debug_level, const char* file_name) {
  log_file = file_name == NULL ? stdout : fopen(file_name, "w");
  atexit(&dispose_of_log);
  current_log_level = debug_level;
}

void check(bool f, const char* message) {
  if (!f) {
    fprintf(log_file, "%s\n", message);
    fflush(log_file);
    print_call_stack();
    exit(1);
  }   
}


void log_fatal(const char* format, ...) {
  time_t  now = time(NULL);
  char    ctimebuf[32],
          *buf = ctime_r(&now, ctimebuf);

  fprintf(log_file, "%-.24s FATAL:", buf);

  va_list va;
  va_start(va, format);
  vfprintf(log_file, format, va);
  va_end(va);
  fflush(log_file);
  print_call_stack();
  exit(1);
}

void slowlog(int lvl, const char* format, ...) {
  if(lvl <= current_log_level) {
    time_t  now = time(NULL);
    char    ctimebuf[32],
            *buf = ctime_r(&now, ctimebuf);

    fprintf(log_file, "%-.24s:", buf);

    va_list va;
    va_start(va, format);
    vfprintf(log_file, format, va);
    va_end(va);
  }
}

}  // namespace slowhttptest
