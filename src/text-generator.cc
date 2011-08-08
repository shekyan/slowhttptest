#include "text-generator.h"
#include "slowlog.h"

#include <algorithm>

using std::string;
using std::generate;

namespace {
  const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"\
                          "0123456789 ,.;:'";
  const int alphabet_size = sizeof(alphabet) / sizeof(alphabet[0]) - 1;
  
  char gen_from_alphabet() {
    return alphabet[rand() % alphabet_size];
  }
}


namespace slowhttptest {
string RandomTextGenerator::GetText(int len) {
  // Dummy.
  string out(len, 'a');
  generate(out.begin(), out.end(), &gen_from_alphabet);
  return out;
}

void RandomTextGenerator::GetText(int len, string* where) {
  CHECK_NOTNULL(where)->resize(len);
  generate(where->begin(), where->end(), &gen_from_alphabet);
}

}  // namespace slowhttptest
