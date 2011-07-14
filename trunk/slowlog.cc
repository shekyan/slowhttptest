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

#include "slowlog.h"

static FILE* log_file = 0;
static bool  g_to_file = false;

void log_init(const bool to_file) {
  g_to_file = to_file;
  if(g_to_file) {
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char filename[24] = {0};
    strftime(filename, 23, "slow_%H%M%S%Y%m%d.log", timeinfo);
    log_file = fopen(filename , "w");
    if(!log_file) {
      printf("Unable to open log file %s for writing: %s", filename, strerror(errno));
      log_file = stdout;
    }
  } else {
    log_file = stdout;
  }
}

void slowlog(const char* format, ...)
{
  time_t  now = time(NULL);
  char    ctimebuf[32],
          *buf = ctime_r(&now, ctimebuf);

  fprintf(log_file, "%-.24s:", buf);

  va_list va;
  va_start(va, format);
  vfprintf(log_file, format, va);
  va_end(va);

  if(g_to_file) {
    fflush(log_file);
  }
}

void log_close() {
  if(g_to_file) {
    fclose(log_file);
  }
}

