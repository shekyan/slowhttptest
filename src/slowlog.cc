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
 *         Victor Agababov vagababov@gmail.com
 *
 * Slow HTTP attack  vulnerability test tool
 *  https://github.com/shekyan/slowhttptest
 *****/


#include <ctime>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "slowlog.h"

namespace {
static FILE* log_file = NULL;
int current_log_level;

}

namespace slowhttptest {
void slowlog_init(int debug_level, const char* file_name) {
  log_file = file_name == NULL ? stdout : fopen(file_name, "w");
  if(!log_file) {
    printf("Unable to open log file %s for writing: %s", file_name,
           strerror(errno));
  }
  current_log_level = debug_level;
}

void check(bool f, const char* message) {
  if (!f) {
    fprintf(log_file, "%s\n", message);
    fflush(log_file);
    exit(1);
  }   
}

void log_fatal(const char* format, ...) {
  const time_t  now = time(NULL);
  char ctimebuf[32];
  const char* buf = ctime_r(&now, ctimebuf);

  fprintf(log_file, "%-.24s FATAL:", buf);

  va_list va;
  va_start(va, format);
  vfprintf(log_file, format, va);
  va_end(va);
  fflush(log_file);
  exit(1);
}

void slowlog(int lvl, const char* format, ...) {
  if(lvl <= current_log_level || lvl == LOG_FATAL) {
    const time_t now = time(NULL);
    char ctimebuf[32];
    const char* buf = ctime_r(&now, ctimebuf);

    fprintf(log_file, "%-.24s:", buf);

    va_list va;
    va_start(va, format);
    vfprintf(log_file, format, va);
    va_end(va);
  }
}

}  // namespace slowhttptest
