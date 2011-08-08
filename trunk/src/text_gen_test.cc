#include <string>
#include "text-generator.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

using namespace slowhttptest;

void random_perf_test_in_place() {
  RandomTextGenerator gen;
  const int sizes[] = {1, 10, 100, 1000, 10000, 100000, 1000000 };
  const int sizes_size = sizeof(sizes) / sizeof(sizes[0]);
  std::string str;
  for (int i = 0; i < sizes_size; ++i) {
    const int cur_size = sizes[i];
    const time_t start = time(NULL);
    for (int j = 0; j < cur_size; ++j) {
      gen.GetText(4096, &str);
    }
    const time_t end = time(NULL);
    printf("Total time to generate %d strings of length %d was %ld\n", cur_size, 4096, end - start);
  }
}

void random_perf_test() {
  RandomTextGenerator gen;
  const int sizes[] = {1, 10, 100, 1000, 10000, 100000, 1000000 };
  const int sizes_size = sizeof(sizes) / sizeof(sizes[0]);
  for (int i = 0; i < sizes_size; ++i) {
    const int cur_size = sizes[i];
    const time_t start = time(NULL);
    for (int j = 0; j < cur_size; ++j) {
      gen.GetText(4096);
    }
    const time_t end = time(NULL);
    printf("Total time to generate %d strings of length %d was %ld\n", cur_size, 4096, end - start);
  }
}

int main() {
  // random_perf_test();
  random_perf_test_in_place();
  return 0;
}

