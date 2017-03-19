# sproxy - a monolithic LAN sleep proxy

This is an implementation of [this concept](https://en.wikipedia.org/wiki/Bonjour_Sleep_Proxy).

Features
* Uses magic packets to wake needed sleeping or hibernating devices which support Wake-on-LAN
* Uses "ARP spoofing" to "stand in" for sleeping or hibernating devices on the LAN
* Periodically polls all configured network devices for sleep status
* IPv4 support (no IPv6 yet)
* Ethernet v2 support
