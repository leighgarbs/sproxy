**[sproxy](https://github.com/leighgarbs/sproxy.git)** -
  Monolithic LAN sleep proxy
==========================================================

For personal use.  This is an implementation of [this concept](https://en.wikipedia.org/wiki/Bonjour_Sleep_Proxy).

## Features ##
* Uses [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) to receive traffic intended for sleeping or hibernating devices on the LAN
* Uses [magic packets](https://en.wikipedia.org/wiki/Wake-on-LAN#Magic_packet) to wake needed sleeping or hibernating devices which support [Wake-on-LAN](https://en.wikipedia.org/wiki/Wake-on-LAN)
* Periodically polls all configured network devices for sleep status using ARP requests
* Configurable
* IPv4 support
* Ethernet v2 support
* Runnable as a daemon
* Logs useful information to log file during runtime

## Goals ##
* Transition to object-oriented C++ (see branch sproxy-class)
* Add tests
* IPv6 support

## Style ##
* No tabs, only spaces
* 4 space indents
* Lines wrap to 80 characters
