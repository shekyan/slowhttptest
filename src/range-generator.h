#ifndef _RANGE_GENERATOR_H_
#define _RANGE_GENERATOR_H_
/*****************************************************************************
*  Copyright 2011 Sergey Shekyan, Victor Agababov
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
 * Authors: Victor Agababov vagababov@gmail.com
 *          Sergey Shekyan shekyan@gmail.com
 *
 * Slow HTTP attack vulnerability test tool
 *  https://github.com/shekyan/slowhttptest
 *****/


#include <string>

namespace slowhttptest {

void GenerateRangeHeader(int start, int step, int limit,
                                  std::string* output);


}  // namespace slowhttptest
#endif  // _RANGE_GENERATOR_H_
