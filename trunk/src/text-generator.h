

#ifndef __SLOW_HTTP_TEST_TEXT_GENERATOR_H__
#define __SLOW_HTTP_TEST_TEXT_GENERATOR_H__

// This file contains classes for text payload generation
// 
// (C) Victor Agababov (vagababov@gmail.com) 2011.

#include <stdlib.h>
#include <time.h>

#include <string>

namespace slowhttptest {

class TextGenerator {
 public:
  TextGenerator() {};
  virtual ~TextGenerator() {}

  virtual std::string GetText(int len) = 0;
  virtual void GetText(int len, std::string* where) = 0;
};


class RandomTextGenerator {
 public:
  RandomTextGenerator() { ::srand(time(NULL)); }
  virtual ~RandomTextGenerator() {}
  virtual void GetText(int len, std::string* where);
  virtual std::string GetText(int len);
};

}  // namespace slowhttptest
#endif  // __SLOW_HTTP_TEST_TEXT_GENERATOR_H__
