// (c) Victor Agababov (vagababov@gmail.com) 2011
// Not reserving most of the rights.
#ifndef _RANGE_GENERATOR_H_
#define _RANGE_GENERATOR_H_

#include <string>

namespace slowhttptest {

void GenerateRangeHeader(int start, int step, int limit,
                                  std::string* output);


}  // namespace slowhttptest
#endif  // _RANGE_GENERATOR_H_
