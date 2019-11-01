/*****************************************************************************
*  Copyright 2011 Victor Agababov
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
 * Author: Victor Agababov vagababov@gmail.com
 *
 * Slow HTTP attack  vulnerability test tool
 *  https://github.com/shekyan/slowhttptest
 *
 *This file contains classes for text payload generation
 *****/

#ifndef __SLOW_HTTP_TEST_TEXT_GENERATOR_H__
#define __SLOW_HTTP_TEST_TEXT_GENERATOR_H__

#include <stdlib.h>
#include <time.h>

#include <string>

namespace slowhttptest {

class TextGenerator {
 public:
  TextGenerator() {};
  virtual ~TextGenerator() {}

  virtual std::string GetText(size_t len) = 0;
  virtual void get_text(size_t len, std::string* where) = 0;
};


class RandomTextGenerator {
 public:
  RandomTextGenerator() { ::srand(time(NULL)); }
  virtual ~RandomTextGenerator() {}
  virtual void get_text(size_t len, std::string* where);
  virtual std::string get_text(size_t len);
};

}  // namespace slowhttptest
#endif  // __SLOW_HTTP_TEST_TEXT_GENERATOR_H__
