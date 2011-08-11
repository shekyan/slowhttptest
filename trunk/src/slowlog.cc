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
static FILE* csv_file = NULL;
static FILE* html_file = NULL;
int current_log_level;

void print_html_header() {
  fprintf(html_file,
      "<html>\r\n \
      <head>\r\n \
      <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\r\n \
      <script type=\"text/javascript\">\r\n \
      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\r\n \
      google.setOnLoadCallback(drawChart);\r\n \
      function drawChart() {\r\n \
      var data = new google.visualization.DataTable();\r\n \
      data.addColumn('string', 'Seconds');\r\n \
      data.addColumn('number', 'Error');\r\n \
      data.addColumn('number', 'Closed');\r\n \
      data.addColumn('number', 'Pending');\r\n \
      data.addColumn('number', 'Connected');\r\n \
      data.addRows([\r\n");
}

void print_html_footer() {
  fprintf(html_file,
      "        ]);\r\n \
      var chart = new google.visualization.AreaChart(document.getElementById('chart_div'));\r\n \
      chart.draw(data, {width: 400, height: 240, title: 'Company Performance',\r\n \
      hAxis: {title: 'Seconds', titleTextStyle: {color: '#FF0000'}},\r\n \
      vAxis: {title: 'Connections', titleTextStyle: {color: '#FF0000'}}\r\n \
      });\r\n \
      }\r\n \
      </script>\r\n \
      </head>\r\n \
      <body>\r\n \
      <div id=\"chart_div\"></div>\r\n \
      </body>\r\n \
      </html>"); 
}


void dispose_of_log() {
  if (log_file && log_file != stdout) {
    fclose(log_file);
  }
  if(csv_file) {
    fclose(csv_file);
  }
  if(html_file) {
    print_html_footer();
    fflush(html_file);
    fclose(html_file);
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
void slowlog_init(int debug_level, const char* file_name, bool need_stats) {
  log_file = file_name == NULL ? stdout : fopen(file_name, "w");
  if(!log_file) {
    printf("Unable to open log file %s for writing: %s", file_name,
           strerror(errno));
  }
  if(need_stats) {
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char csv_file_name[32] = {0};
    char html_file_name[32] = {0};
    strftime(csv_file_name, 22, "slow_%H%M%Y%m%d.csv", timeinfo);
    strftime(html_file_name, 22, "slow_%H%M%Y%m%d.html", timeinfo);
    csv_file = fopen(csv_file_name , "w");
    if(!csv_file) {
      printf("Unable to open csv file %s for writing: %s\n",
             csv_file_name,
             strerror(errno));
    } else {
      fprintf(csv_file, "Seconds,Error,Closed,Pending,Connected\n");
    }
    html_file = fopen(html_file_name , "w");
    if(!html_file) {
      printf("Unable to open html file %s for writing: %s\n",
          html_file_name,
          strerror(errno));
    } else {
      print_html_header(); 
    }
  }
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
  const time_t  now = time(NULL);
  char ctimebuf[32];
  const char* buf = ctime_r(&now, ctimebuf);

  fprintf(log_file, "%-.24s FATAL:", buf);

  va_list va;
  va_start(va, format);
  vfprintf(log_file, format, va);
  va_end(va);
  fflush(log_file);
  print_call_stack();
  exit(1);
}

void dump_csv(const char* format, ...) {
  va_list va;
  va_start(va, format);
  vfprintf(csv_file, format, va);
  fflush(csv_file);
  va_end(va);
} 

void dump_html(const char* format, ...) {
  va_list va;
  va_start(va, format);
  vfprintf(html_file, format, va);
  fflush(html_file);
  va_end(va);


}

void slowlog(int lvl, const char* format, ...) {
  if(lvl <= current_log_level) {
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
