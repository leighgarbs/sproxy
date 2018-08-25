#if !defined DEVICE_HPP
#define DEVICE_HPP

#include <vector>

#include "Ipv4Address.hpp"
#include "MacAddress.hpp"

// Details all needed information about a device on the LAN this program may
// proxy for
struct Device
{
  // Whether or not this device is believed to currently be sleeping
  bool is_sleeping;

  // Whether or not this device is awake; used in short-term sleep testing
  bool is_awake;

  // IP address
  Ipv4Address ip_address;

  // MAC address
  MacAddress mac_address;

  // List of ports this device considers important; it will be woken if traffic
  // comes in on one of them
  std::vector<unsigned short> ports;

  // Last time this device was issued a WOL frame
  time_t last_wol_timestamp;

  // Last time a gratuitous ARP was issued on behalf of this device
  time_t last_garp_timestamp;
};

#endif
