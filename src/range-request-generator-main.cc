// (c) Victor Agababov (vagababov@gmail.com) 2011
// Not reserving most of the rights.
#include "range-request-generator.h"

#include <stdio.h>

#include <string>

using std::string;

using slowhttptest::GenerateHeadRequestWithRange;

int main(int argc, char** argv) {
  string str;
  GenerateHeadRequestWithRange("GET", "/index.html", "localhost", 5, 2, 2000,
                               &str);
  printf("Data:\n%s\n", str.c_str());
  return 0;
}
