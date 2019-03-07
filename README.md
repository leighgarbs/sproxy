**[tools-cpp](https://github.com/leighgarbs/tools-cpp)** -
  Generalized cross-project C++ tools
==========================================================

For personal use.  This is an implementation of [this concept](https://en.wikipedia.org/wiki/Bonjour_Sleep_Proxy).

## Features ##
* Uses [magic packets](https://en.wikipedia.org/wiki/Wake-on-LAN#Magic_packet) to wake needed sleeping or hibernating devices which support Wake-on-LAN
* Uses "ARP spoofing" to "stand in" for sleeping or hibernating devices on the LAN
* Periodically polls all configured network devices for sleep status
* IPv4 support (no IPv6 yet)
* Ethernet v2 support

## Goals ##
* Transition to object-oriented C++ (see branch sproxy-class)
* Add tests

## Style ##
* No tabs, only spaces
* 4 space indents
* Lines wrap to 80 characters
