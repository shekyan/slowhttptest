// None of the rights are reserved.
// (C) by Victor Agababov (vagababov@gmail.com) 2011
#include "slowstats.h"
#include <stdio.h>
#include <vector>
#include <string>

using std::string;

using namespace slowhttptest;
using std::vector;

int main() {
  vector<StatsDumper*> dumpers;
  dumpers.push_back(new HTMLDumper("test.html"));
  dumpers.push_back(new CSVDumper("test.csv", "Seconds,Error,Closed,Pending,Connected\n"));
  //dumpers.push_back(new CSVDumper("test.csv"));
  for (int i = 0; i < dumpers.size(); ++i) {
    if (!dumpers[i]->Initialize()) {
      fprintf(stderr, "ERROR ERROR ERROR. File cannot be opened");
      return 1;
    }
  }
  for (int i = 0; i < dumpers.size(); ++i) {
    dumpers[i]->WriteStats("%d,%d,%d,%d,%d", 1, 2, 3, 4, 5, 6);  
    dumpers[i]->WriteStats("%d,%d,%d,%d,%d", 2, 3, 4, 5, 1, 1);  
    dumpers[i]->WriteStats("%d,%d,%d,%d,%d", 3, 4, 5, 1, 2, 2);  
    dumpers[i]->WriteStats("%d,%d,%d,%d,%d", 4, 5, 1, 2, 3, 3);  
    dumpers[i]->WriteStats("%d,%d,%d,%d,%d", 5, 1, 2, 3, 4, 4);  
  }
  for (int i = 0; i < dumpers.size(); ++i) {
    delete dumpers[i];
  }
  dumpers.clear();
  return 0;
}

