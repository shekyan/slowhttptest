// (c) Victor Agababov (vagababov@gmail.com) 2011
// Not reserving most of the rights.
#include "range-generator.h"

#include <sstream>

#include "slowlog.h"


using std::string;

namespace {
const char kVersion[] = " HTTP/1.1\r\nHost: ";
}  // namespace

namespace slowhttptest {

void GenerateRangeHeader(int start, int step, int limit,
                                  string* output) {
  std::ostringstream oss;
  oss << "Range: bytes=0-,";
  for (int i = 0; i < limit; i+= step) {
    oss << start << '-' << i << ',';
  }
  oss << start << '-' << limit << "\r\nAccept-Encoding: gzip\r\nConnection:"
      << " close\r\n\r\n";
  output->append(oss.str());

}

}  // namespace slowhttptest
