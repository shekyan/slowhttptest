// Copyright, yo by Victor Agababov (vagababov@gmail.com) 2011

#ifndef __SLOW_HTTP_TEST_STATS_H_
#define __SLOW_HTTP_TEST_STATS_H_

#include <string>
#include <stdio.h>

namespace slowhttptest {

class StatsDumper { 
 public:
  StatsDumper(const std::string& file_name)
    : file_name_(file_name),
      file_(0) {
  }

  virtual ~StatsDumper() {
    if (file_) {
      fclose(file_);
    }
  }

  virtual bool Initialize();
  virtual void WriteStats(const char* format, ...);

 protected:
  // If derived classes need to write anything.
  void WriteString(const char* str);
  bool IsOpen() const { return file_ != NULL; }
  // If subclass needs to write something before stats, that's where 
  // it should go.
  virtual void PreWrite() {}

  // If subclass needs to write anything after stats, that's where
  // it should go.
  virtual void PostWrite();
  
  // If SubClass needs to modify format string somehow
  // that is the place to do it.
  virtual std::string ModifyFormatString(const char* format) { return format; }

 private:
  const std::string file_name_;
  FILE* file_;
};


class HTMLDumper : public StatsDumper {
 public:
  HTMLDumper(const std::string& file_name)
    : StatsDumper(file_name) {
  }
  virtual ~HTMLDumper();

  virtual bool Initialize();

 private:
  virtual void PreWrite();
  virtual void PostWrite();
  // We need to escap with ' the first parameter.
  virtual std::string ModifyFormatString(const char* format);
  void WriteHeader();
  void WriteFooter();
};

class CSVDumper : public StatsDumper {
 public:
  CSVDumper(const std::string& file_name);
  CSVDumper(const std::string& file_name, const std::string& header);

  virtual ~CSVDumper() {}  
  virtual bool Initialize();

 private:
  const std::string header_;
};

}  // namespace slowhttptest


#endif  // __SLOW_HTTP_TEST_STATS_H_

