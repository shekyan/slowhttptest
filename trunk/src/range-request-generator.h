// (c) Victor Agababov (vagababov@gmail.com) 2011
// Not reserving most of the rights.
#include <string>

namespace slowhttptest {

// Generates a HEAD request with repeating range fields, consisting of
// start-0, start-1, ..., start-limit blocks.
// path: the path on the server to request.
// host: server host
// start: the start element in the range elements
// step: is the stepping of right range
// limit: the max range
// output: will contain the generated HEAD request.
void GenerateHeadRequestWithRange(const std::string& path, const std::string& host,
                                  int start, int step, int limit,
                                  std::string* output);


}  // namespace slowhttptest
