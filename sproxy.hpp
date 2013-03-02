// Sleep proxy header
// Leigh Garbs

#if !defined SPROXY_HPP
#define SPROXY_HPP

#include <ctime>
#include <vector>

// Details all needed information about a device on the LAN this program may
// proxy for
struct Device
{
  // Whether or not this device is believed to currently be sleeping
  bool is_sleeping;

  // Whether or not this device is awake; used in short-term sleep testing
  bool is_awake;

  // IP address
  unsigned char ip_address[4];

  // MAC address
  unsigned char mac_address[6];

  // List of ports this device considers important; it will be woken if traffic
  // comes in on one of them
  std::vector<unsigned short> ports;

  // Last time this device was issued a WOL frame
  time_t last_wol_timestamp;

  // Last time a gratuitous ARP was issued on behalf of this device
  time_t last_garp_timestamp;
};

// Holds info on all monitored devices
extern std::vector<Device> devices;

// Name of the interface on which proxying will take place
extern char* interface_name;

// Stores the MAC of the device this proxy is using to monitor network traffic
extern char own_mac[6];

// IP address assigned to interface with name interface_name
extern char own_ip[4];


// Sends a gratuitous ARP for the specified IP address/MAC address combo
void send_garp(const unsigned char* ip_address,
	       const unsigned char* mac_address);

#endif
