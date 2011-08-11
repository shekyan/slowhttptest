// Copyright, yo by Victor Agababov (vagababov@gmail.com) 2011

#include "slowstats.h"
#include "slowlog.h"
#include <stdarg.h>
#include <string>

using std::string;

namespace {

const char* HTML_HEADER =
      "<!-- SlowHTTPTestAnalysys chart (c) Sergey Shekyan, Victor Agababov 2011  -->\
      <html>\r\n \
      <head>\r\n \
      <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\r\n \
      <script type=\"text/javascript\">\r\n \
      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\r\n \
      google.setOnLoadCallback(drawChart);\r\n \
      function drawChart() {\r\n \
        var data = new google.visualization.DataTable();\r\n \
        data.addColumn('string', 'Seconds');\r\n \
        data.addColumn('number', 'Error');\r\n \
        data.addColumn('number', 'Closed');\r\n \
        data.addColumn('number', 'Pending');\r\n \
        data.addColumn('number', 'Connected');\r\n \
        data.addRows([\r\n";

const char* HTML_FOOTER = 
      "        ]);\r\n \
      var chart = new google.visualization.AreaChart(document.getElementById('chart_div'));\r\n \
      chart.draw(data, {'width': 400, 'height': 240, 'title': 'Company Performance',\r\n \
      hAxis: {'title': 'Seconds', 'titleTextStyle': {color: '#FF0000'}},\r\n \
      vAxis: {'title': 'Connections', 'titleTextStyle': {color: '#FF0000'}}\r\n \
      });\r\n \
      }\r\n \
      </script>\r\n \
      <title>SlowHTTPTest(tm) Connection Results</title>\
      </head>\r\n \
      <body>\r\n \
      <div id=\"chart_div\"></div>\r\n \
      </body>\r\n \
      </html>\n";
}

namespace slowhttptest {

bool StatsDumper::Initialize() {
  file_ = fopen(file_name_.c_str(), "w");
  return file_ != NULL;
}

void StatsDumper::WriteStats(const char* format, ...) {
  CHECK_NOTNULL(file_);
  CHECK_NOTNULL(format);
  // Also must be non-empty.
  check(*format != 0, "Format string cannot be empty");

  PreWrite();
  const string new_format = ModifyFormatString(format);

  va_list va;
  va_start(va, format);
  vfprintf(file_, new_format.c_str(), va);
  va_end(va);
  PostWrite();
  fflush(file_);
}


void StatsDumper::PostWrite() {
  fprintf(file_, "\n");
}

void StatsDumper::WriteString(const char* str) {
  CHECK_NOTNULL(file_);
  CHECK_NOTNULL(str);
  if (*str) {
    fprintf(file_, "%s", str);
  }
}

CSVDumper::CSVDumper(const string& file_name, const string& header)
    : StatsDumper(file_name),
      header_(header) {
}

CSVDumper::CSVDumper(const string& file_name)
    : StatsDumper(file_name) {
}

bool CSVDumper::Initialize() {
  if (StatsDumper::Initialize()) {
    WriteString(header_.c_str());
    return true;
  }
  return false;
}

bool HTMLDumper::Initialize() {
  if (StatsDumper::Initialize()) {
    WriteHeader();
    return true;
  }
  return false;
}

HTMLDumper::~HTMLDumper() {
  if (IsOpen()) {
    WriteFooter();
  }
}

void HTMLDumper::WriteHeader() {
  WriteString(HTML_HEADER);
}

void HTMLDumper::WriteFooter() {
  WriteString(HTML_FOOTER);
}

void HTMLDumper::PreWrite() {
  WriteString("[");
}

void HTMLDumper::PostWrite() {
  WriteString("],\n");
}

string HTMLDumper::ModifyFormatString(const char* format) {
  string new_format(format);
  string::size_type pos = new_format.find('%');
  if (pos != string::npos) {
    // There must be something after the first %.
    check(new_format.size() > pos + 1, "Incorrect format specification");
    new_format.insert(pos + 2, 1, '\'');
    new_format.insert(pos, 1, '\'');
  }
  return new_format;
}

}  // namespace slowhttptest
