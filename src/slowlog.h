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
 *
 *  Simple logging with verbosity levels
 *****/
#ifndef _SLOWLOG_H_
#define _SLOWLOG_H_
// log levels
#define LOG_FATAL   0
#define LOG_INFO    1
#define LOG_ERROR   2
#define LOG_WARN    3
#define LOG_DEBUG   4

#ifdef USE_COLOR
#  define cBLK "\x1b[0;30m"
#  define cRED "\x1b[0;31m"
#  define cGRN "\x1b[0;32m"
#  define cBRN "\x1b[0;33m"
#  define cBLU "\x1b[0;34m"
#  define cMGN "\x1b[0;35m"
#  define cCYA "\x1b[0;36m"
#  define cNOR "\x1b[0;37m"
#  define cGRA "\x1b[1;30m"
#  define cLRD "\x1b[1;31m"
#  define cLGN "\x1b[1;32m"
#  define cYEL "\x1b[1;33m"
#  define cLBL "\x1b[1;34m"
#  define cPIN "\x1b[1;35m"
#  define cLCY "\x1b[1;36m"
#  define cBRI "\x1b[1;37m"
#  define cRST "\x1b[0m"
#else
#  define cBLK ""
#  define cRED ""
#  define cGRN ""
#  define cBRN ""
#  define cBLU ""
#  define cMGN ""
#  define cCYA ""
#  define cNOR ""
#  define cGRA ""
#  define cLRD ""
#  define cLGN ""
#  define cYEL ""
#  define cLBL ""
#  define cPIN ""
#  define cLCY ""
#  define cBRI ""
#  define cRST ""
#endif /* ^USE_COLOR */

namespace slowhttptest {
void slowlog_init(int debug_level, const char* file_name);
void slowlog(int lvl, const char* format, ...);
void log_fatal(const char* format, ...);
void check(bool f, const char* message);
template <class T> T* check_not_null(T* p, const char* message) {
  check(p != 0, message);
  return p;
}
}  // namespace slowhttptest

#define CHECK_NOTNULL(p) slowhttptest::check_not_null(p, #p" is NULL")

#endif  // _SLOWLOG_H_
