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

#include "text-generator.h"
#include "slowlog.h"

#include <algorithm>

using std::string;
using std::generate;

namespace {
  const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
                          "0123456789";
  const int alphabet_size = sizeof(alphabet) / sizeof(alphabet[0]) - 1;
  
  char gen_from_alphabet() {
    return alphabet[rand() % alphabet_size];
  }
}


namespace slowhttptest {
string RandomTextGenerator::get_text(size_t len) {
  int rand_len = (rand() % (len ? len : 1));
  string out(rand_len ? rand_len : 1, 'a');
  generate(out.begin(), out.end(), &gen_from_alphabet);
  return out;
}

void RandomTextGenerator::get_text(size_t len, string* where) {
  CHECK_NOTNULL(where)->resize(len);
  generate(where->begin(), where->end(), &gen_from_alphabet);
}

}  // namespace slowhttptest

