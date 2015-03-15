# slowhttptest #

SlowHTTPTest is a highly configurable tool that simulates some Application Layer Denial of Service attacks. It works on majority of Linux platforms, OSX and Cygwin - a Unix-like environment and command-line interface for Microsoft Windows.

It implements most common low-bandwidth Application Layer DoS attacks, such as **[slowloris](http://ha.ckers.org/slowloris/)**, **[Slow HTTP POST](http://www.darkreading.com/vulnerability-management/167901026/security/attacks-breaches/228000532/index.html)**, **[Slow Read attack](https://community.qualys.com/blogs/securitylabs/2012/01/05/slow-read)** (based on TCP persist timer exploit) by draining concurrent connections pool, as well as **[Apache Range Header attack](ApacheRangeTest.md)** by causing very significant memory and CPU usage on the server.


Slowloris and Slow HTTP POST DoS attacks rely on the fact that the HTTP protocol, by design, requires requests to be completely received by the server before they are processed. If an HTTP request is not complete, or if the transfer rate is very low, the server keeps its resources busy waiting for the rest of the data. If the server keeps too many resources busy, this creates a denial of service. This tool is sending partial HTTP requests, trying to get denial of service from target HTTP server.


[Slow Read DoS attack](SlowReadTest.md) aims the same resources as slowloris and slow POST, but instead of prolonging the request, it sends legitimate HTTP request and reads the response slowly.

[Installation and usage examples](InstallationAndUsage.md)

[How I knocked down 30 servers using slowhttptest](http://blog.shekyan.com/2012/01/how-i-knocked-down-30-servers-from-one-laptop.html)

[Slow Read DoS attack explained](http://blog.shekyan.com/2012/01/are-you-ready-for-slow-reading.html)

[Test results of popular HTTP servers](http://blog.shekyan.com/2011/09/testing-web-servers-for-slow-http-attacks.html)

[How to protect against slow HTTP DoS attacks](http://blog.shekyan.com/2011/11/how-to-protect-against-slow-http-attacks.html)




Many thanks to [Tigran Gevorgyan](http://code.google.com/u/tigran_gevorgyan@hotmail.com)  and [Victor Agababov](http://code.google.com/u/107950426759701528367/) for tons of help and support.
The logo is from http://openclipart.org/detail/168031/.

Some links to the media coverage, for historical purposes:

[ArsTechnica](http://arstechnica.com/business/2012/01/new-slow-motion-dos-attack-just-a-few-pcs-little-fear-of-detection/)
[The Verge](http://www.theverge.com/2012/1/7/2688675/new-denial-of-service-vulnerability-detailed-doesnt-require-many-pcs)
[TechWorld](http://news.techworld.com/security/3328184/invisible-dos-attack-devised-by-white-hat-hacker/)
[DarkReading](http://www.darkreading.com/advanced-threats/167901091/security/attacks-breaches/232301367/new-denial-of-service-attack-cripples-web-servers-by-reading-slowly.html)

## 25 November 2013 ##

SlowHTTPTest version1.6 is out. Thanks to Comcast for not having Internet for two days, managed to do a lot of things. This release includes all the small bug fixes that were sitting in SVN for over a year, usability improvements and better reporting. Check it out and leave some feedback!
[Blog post with changes and hints](http://blog.shekyan.com/2013/11/slowhttptest-v16-is-out.html)

## 7 September 2012 ##

Released version 1.5 with improved CPU utilization, some bug fixes, and proxy support, which means you can direct either probe or entire traffic through a specified web proxy.

## 28 January 2012 ##

Released version 1.4 with poll() support, which means slowhttptest is not limited to 1024 connections anymore. Added man page, fixed several bugs, including build issues on FreeBSD and cygwin.

## 28 December 2011 ##

Released version 1.3 with [Slow Read Denial of Service attack](SlowReadTest.md) support.

Check out the video with demonstration of the attack:

<a href='http://www.youtube.com/watch?feature=player_embedded&v=Jq1nDEuvGjg' target='_blank'><img src='http://img.youtube.com/vi/Jq1nDEuvGjg/0.jpg' width='425' height=344 /></a>


## 26 September 2011 ##

Released version 1.2. The major new feature is the indicator of HTTP server's availability. Instead of refreshing the page in the browser to figure out if the web server is down, let slowhttptest to request the target web page every second and track the status in log messages and statistics files. [Installation and usage examples](InstallationAndUsage.md) page is updated with detailed description of how probe connection should be configured and used.

Charts now show intervals when server was not available:

![![](https://lh5.googleusercontent.com/-vU4CrGXWOKQ/ToEhHQXKP0I/AAAAAAAAA6g/7GV2rnidAVI/s400/nginx_new.png)](https://lh5.googleusercontent.com/-vU4CrGXWOKQ/ToEhHQXKP0I/AAAAAAAAA6g/7GV2rnidAVI/s800/nginx_new.png)

## 27 August 2011 ##

Released version 1.1 that includes test mode for Apache Range header handling DoS vulnerability test

## 24 August 2011 ##

First version of slowhttptest is released.
