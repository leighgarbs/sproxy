// LAN sleep proxy
// Leigh Garbs

// This program acts as a sleep proxy for the attached LAN.  It attempts to
// recognize sleeping LAN devices and wake them if they have important traffic
// inbound.


#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "LinuxRawSocket.hpp"
#include "Log.hpp"
#include "arp_ipv4.h"
#include "ethernet_ii_header.h"
#include "ipv4_header.h"
#include "tcp_header.h"


// Length of the input buffers used during config and default file parsing
#define PARSING_BUFFER_LENGTH 1000


// Filename of the default settings file, typically located in /etc/default
std::string default_filename = "/etc/sproxy/config";

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

// Stores known devices to monitor
std::vector<Device> devices;

// Stores a template ARP request used when checking if monitored hosts are
// asleep
char arp_request[sizeof(ethernet_ii_header) + sizeof(arp_ipv4)];

// Stores the MAC of the device this proxy is using to monitor network traffic
char own_mac[6];

// IP address assigned to interface with name interface_name
char own_ip[4];

// Is this host big-endian?
bool is_big_endian;

// Used to log important sproxy activities
Log log;


// THESE CONFIGURATION VARIABLES ARE SET BASED ON THE DEFAULT FILE AND/OR
// PROGRAM ARGUMENTS

// Name of the interface on which proxying will take place
std::string interface_name = "eth0";

// Filename of the config file, typically located in /etc
std::string config_filename = "/etc/sproxy/devices";

// Filename of the log file, typically located in /var/log
std::string log_filename = "/var/log/sproxy.log";

// Filename of the file in which PID is stored
std::string pid_filename = "/var/run/sproxy.pid";


// Whether or not this process should daemonize
bool daemonize = false;

// Length of time between device checks
unsigned int device_check_period = 10;

// How long to wait for responses from monitored devices after querying them
unsigned int device_response_grace_period = 1;

// Aggressively keep the network up to date on changing ARP status?
bool aggressive_garp = true;


//=============================================================================
// Performs any clean up that must be done before the program halts
//=============================================================================
void clean_exit(int unused)
{
  // Log that the service is stopping
  log.write("Service stopping");

  // Delete the PID file
  unlink(pid_filename.c_str());

  // We're done, exit
  exit(0);
}

//=============================================================================
// Writes the PID of the calling process to file
//=============================================================================
void write_pid_to_file(const std::string& pid_filename)
{
    // Get the PID
    int pid = getpid();

    std::ofstream out_stream(pid_filename.c_str());
    out_stream << pid << "\n";
    out_stream.close();
}

//=============================================================================
// Processes program arguments
//=============================================================================
bool process_arguments(int argc, char** argv)
{
  // Loop over all the arguments, and process them
  for (int arg = 1; arg < argc; arg++)
  {
    // Argument -c specifies the config file filename
    if (strcmp("-c", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      config_filename = argv[arg];
    }
    // Argument -D indicates this process should daemonize itself
    else if (strcmp("-D", argv[arg]) == 0)
    {
      daemonize = true;
    }
    // Argument -d specifies the default file filename
    else if (strcmp("-d", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      default_filename = argv[arg];
    }
    // Argument -i specifies an interface to monitor
    else if (strcmp("-i", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      interface_name = argv[arg];
    }
    // Argument -l specifies the log file filename
    else if (strcmp("-l", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      interface_name = argv[arg];
    }
    else if (strcmp("--pidfile", argv[arg]) == 0 && arg + 1 < argc)
    {
      arg++;

      pid_filename = argv[arg];
    }

  }

  // If execution reaches here there was an acceptable set of arguments provided
  return true;
}

//=============================================================================
// Obtains the MAC and IP address of the interface to be used
//=============================================================================
void obtain_own_mac_and_ip()
{
  // Getting MAC and IP addresses requires a socket, doesn't matter what kind
  int sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock_fd == -1)
  {
    // If something goes wrong, print an error message and quit
    perror(0);
    clean_exit(0);
  }

  // Fill out an ifreq with name of the target interface
  ifreq iface;
  strcpy(iface.ifr_name, interface_name.c_str());

  // Request our MAC address
  if (ioctl(sock_fd, SIOCGIFHWADDR, &iface) == -1)
  {
    // If something goes wrong, print an error message and quit
    perror(0);
    clean_exit(0);
  }

  // Initialize own_mac
  memcpy(own_mac, iface.ifr_hwaddr.sa_data, 6);

  // Request our IP address
  if (ioctl(sock_fd, SIOCGIFADDR, &iface) == -1)
  {
    // If something goes wrong, print an error message and quit
    perror(0);
    clean_exit(0);
  }

  // Initialize own IP address
  sockaddr_in* temp_addr = (sockaddr_in*)&iface.ifr_addr;
  memcpy(own_ip, (const void*)(&(temp_addr->sin_addr.s_addr)), 4);
}

//=============================================================================
// Gets a single time value (in seconds) from a timeval structure
//=============================================================================
double get_time(const timeval& time)
{
  return time.tv_sec + static_cast<double>(time.tv_usec) / 1e6;
}

//==============================================================================
// Converts binary MAC address to a string representation
//==============================================================================
void mac_to_string(const unsigned char* const mac,
                   std::string&               mac_str)
{
  char mac_cstr[18];
  sprintf(mac_cstr, "%02x:%02x:%02x:%02x:%02x:%02x",
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  mac_str = mac_cstr;
}

//==============================================================================
// Converts binary IP address to a string representation
//==============================================================================
void ip_to_string(const unsigned char* const ip,
                  std::string&               ip_str)
{
  char ip_cstr[16];
  sprintf(ip_cstr, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

  ip_str = ip_cstr;
}

//=============================================================================
// Issuing a WOL
//=============================================================================
void log_issuing_wol(const unsigned char* const mac_address,
                     const unsigned char* const ip_address,
                     const unsigned char* const requesting_mac,
                     const unsigned char* const requesting_ip)
{
  // Parse target mac into a string
  std::string mac_address_str;
  mac_to_string(mac_address, mac_address_str);

  // Parse target ip into a string
  std::string ip_address_str;
  ip_to_string(ip_address, ip_address_str);

  // Parse requesting mac into a string
  std::string requesting_mac_str;
  mac_to_string(requesting_mac, requesting_mac_str);

  std::string requesting_ip_str;
  ip_to_string(requesting_ip, requesting_ip_str);

  // Issue the log message
  log.write("Issuing WOL for " + mac_address_str + " (" + ip_address_str
            + ") on behalf of " + requesting_mac_str + " (" + requesting_ip_str
            + ")");
}

//=============================================================================
// Issuing a gratuitous ARP
//=============================================================================
void log_issuing_garp(const unsigned char* const ip_address,
                      const unsigned char* const mac_address,
                      const unsigned char* const traffic_mac = 0)
{
  std::string mac_address_str;

  // See if the MAC address we're dealing with is the proxy's MAC address, and
  // if it is, we'll print 'self' in the log in place of the proxy's MAC,
  // because this is easier to understand
  if (memcmp(own_mac, mac_address, 6) == 0)
  {
    mac_address_str = "self";
  }
  else
  {
    // Parse mac address into a string
    mac_to_string(mac_address, mac_address_str);
  }

  // Parse IP address into a string
  std::string ip_address_str;
  ip_to_string(ip_address, ip_address_str);

  // Define message now, may be appended to later
  std::string message = "Issuing gratuitous ARP associating " +
    ip_address_str + " with " + mac_address_str;

  // If a traffic mac was given, incorporate that into the log message
  if (traffic_mac)
  {
    // Parse traffic mac into a string
    std::string traffic_mac_str;
    mac_to_string(traffic_mac, traffic_mac_str);

    // Append to previously defined message
    message += " on behalf of " + traffic_mac_str;
  }

  // Issue the log message
  log.write(message);
}

//=============================================================================
// Device has awoken
//=============================================================================
void log_device_awake(const unsigned char* const ip_address,
                      const unsigned char* const mac_address)
{
  // Parse mac into string
  std::string mac_address_str;
  mac_to_string(mac_address, mac_address_str);

  // Parse IP address into string
  std::string ip_address_str;
  ip_to_string(ip_address, ip_address_str);

  // Issue the log message
  log.write("Device " + mac_address_str + " (" + ip_address_str + ") is awake");
}

//=============================================================================
// Device has fallen asleep
//=============================================================================
void log_device_asleep(const unsigned char* const ip_address,
                       const unsigned char* const mac_address)
{
  // Parse mac into string
  std::string mac_address_str;
  mac_to_string(mac_address, mac_address_str);

  // Parse IP address into string
  std::string ip_address_str;
  ip_to_string(ip_address, ip_address_str);

  // Issue the log message
  log.write("Device " + mac_address_str + " (" + ip_address_str + ") is asleep");
}

//=============================================================================
// Parses sproxy defaults file
//=============================================================================
void parse_default_file(const std::string& filename)
{
  // Open the defaults file
  std::ifstream default_stream(filename.c_str());
  if (!default_stream.good())
  {
    return;
  }

  // Initialize some stuff to be used during parsing
  char default_line_buffer[PARSING_BUFFER_LENGTH];
  std::istringstream convert_to_number;

  // Read the entire defaults file
  while(!default_stream.eof())
  {
    // Read a line of the file
    default_stream.getline(default_line_buffer, PARSING_BUFFER_LENGTH);

    // Convert it to a string
    std::string default_line_string = default_line_buffer;

    // Ignore the line if it's a comment
    if (default_line_string[0] == '#')
    {
      continue;
    }

    // Search through the line for a '='
    size_t equal_sign = default_line_string.find('=');

    // If there isn't an equal sign, or the equal sign is at the beginning or
    // end of the buffer, just go to the next line because this line is bad
    if (equal_sign == std::string::npos ||
        equal_sign == 0 ||
        equal_sign == default_line_string.length())
    {
      continue;
    }

    // Pull out the strings on the left and right of the equal sign
    std::string left_side  = default_line_string.substr(0, equal_sign);
    std::string right_side = default_line_string.substr(equal_sign + 1,
                                                        std::string::npos);

    // Now set the appropriate variable based on what was just parsed
    if (left_side == "ETH_INTERFACE")
    {
      interface_name = right_side;
    }
    else if (left_side == "CONFIG_FILE")
    {
      config_filename = right_side;
    }
    else if (left_side == "LOG_FILE")
    {
      log_filename = right_side;
    }
    else if (left_side == "PID_FILE")
    {
      pid_filename = right_side;
    }
    else if (left_side == "DAEMONIZE")
    {
      daemonize = right_side == "yes";
    }
    else if (left_side == "DEVICE_CHECK_PERIOD")
    {
      // Convert the right side to a number, that's what it's supposed to be
      convert_to_number.clear();
      convert_to_number.str(right_side);
      convert_to_number >> device_check_period;
    }
    else if (left_side == "DEVICE_RESPONSE_GRACE_PERIOD")
    {
      convert_to_number.clear();
      convert_to_number.str(right_side);
      convert_to_number >> device_response_grace_period;
    }
    else if (left_side == "AGGRESSIVE_GARP")
    {
      if (right_side == "yes")
      {
        aggressive_garp = true;
      }
      else
      {
        aggressive_garp = false;
      }
    }
  }
}

//=============================================================================
// Parses sproxy config file
//=============================================================================
void parse_config_file(const std::string& filename)
{
  // Open the file containing the devices to proxy for
  std::ifstream config_stream(filename.c_str());

  // Initialize some stuff to be used during parsing
  char config_line_buffer[PARSING_BUFFER_LENGTH];
  std::istringstream config_line;
  std::string token;
  unsigned int line_number = 0;

  // Start reading config
  while(!config_stream.eof())
  {
    // Read a line of device information
    config_stream.getline(config_line_buffer, PARSING_BUFFER_LENGTH);

    // Increment line counter
    line_number++;

    // If nothing was read, we're done parsing input
    if (config_stream.gcount() < 1)
    {
      break;
    }

    // Clear status from previous iterations
    config_line.clear();

    // Convert to a string stream
    config_line.str(config_line_buffer);

    // Read the MAC address
    config_line >> token;

    // If the line begins with a #, it's a comment line; move on to the next
    // line
    if (token[0] == '#')
    {
      continue;
    }

    // If we just read a properly formatted MAC address, the token's length will
    // be 12 characters (2 for each byte) plus 5 colons
    if (token.size() != 17)
    {
      // If the MAC parsing failed, tell the user why and exit
      std::cerr << "Error in " << filename << "\n"
                << "Could not parse MAC address on line " << line_number
                << "\n";
      clean_exit(0);
    }

    // Now that we know we have a new device to monitor, push a new Device onto
    // the list of devices to track it
    Device new_device;
    devices.push_back(new_device);

    // Scan the device's MAC address into temporary storage
    int temp_mac[6];
    if (sscanf(token.c_str(),
               "%2x:%2x:%2x:%2x:%2x:%2x",
               &temp_mac[0],
               &temp_mac[1],
               &temp_mac[2],
               &temp_mac[3],
               &temp_mac[4],
               &temp_mac[5]) != 6)
    {
      // If the MAC parsing failed, tell the user why and exit
      std::cerr << "Error in " << filename << "\n"
                << "Could not parse MAC address on line " << line_number
                << "\n";
      clean_exit(0);
    }

    // Copy from temporary storage into permanent storage
    for (unsigned int i = 0; i < 6; i++)
    {
      devices.back().mac_address[i] = static_cast<unsigned char>(temp_mac[i]);
    }

    // Read in the device's IPv4 address
    config_line >> token;

    unsigned int temp_ip[4];
    if (sscanf(token.c_str(),
               "%u.%u.%u.%u",
               &temp_ip[0],
               &temp_ip[1],
               &temp_ip[2],
               &temp_ip[3]) != 4)
    {
      // If the IP parsing failed, tell the user why and exit
      std::cerr << "Could not parse IP address on line " << line_number << "\n";
      clean_exit(0);
    }

    // Copy from temporary storage into permanent storage
    for (unsigned int i = 0; i < 4; i++)
    {
      devices.back().ip_address[i] = static_cast<unsigned char>(temp_ip[i]);
    }

    // Now read each of this device's important ports
    while(!config_line.eof())
    {
      // First, read into a string
      config_line >> token;
      if (config_line.fail())
      {
        // If nothing was read, we're done with this device
        break;
      }

      // Try to convert the token that was just read into a port number
      unsigned short port;
      std::istringstream convert_stream(token);
      convert_stream >> port;

      // Check for errors
      if (convert_stream.fail())
      {
        // If something else went wrong, inform the user and quit
        std::cerr << "Unable to parse port on line " << line_number << "\n";
        clean_exit(0);
      }

      // Add the port to the device's list
      devices.back().ports.push_back(port);
    }

    // Initially mark the device as awake; if it really isn't awake, this
    // program will figure it out shortly
    devices.back().is_sleeping = false;
    devices.back().is_awake    = true;

    // Last WOL timestamp init
    devices.back().last_wol_timestamp = 0;

    // Last gratuitous ARP timestamp init
    devices.back().last_garp_timestamp = 0;
  }
}

//=============================================================================
// Initializes the arp_request global variable with a template ARP request
//=============================================================================
void initialize_arp_request()
{
  ethernet_ii_header* arp_req_eth_hdr = (ethernet_ii_header*)arp_request;
  arp_ipv4* arp_req_arp =
    (arp_ipv4*)(arp_request + sizeof(ethernet_ii_header));

  // Set destination MAC
  memset(arp_req_eth_hdr->mac_destination, 0xff, 6);

  // Set source MAC
  memcpy(arp_req_eth_hdr->mac_source, own_mac, 6);

  // Set Ethertype
  arp_req_eth_hdr->ethertype[0] = 0x08;
  arp_req_eth_hdr->ethertype[1] = 0x06;

  // Set hardware, protocol type and length
  arp_req_arp->htype[0] = 0x00;
  arp_req_arp->htype[1] = 0x01;
  arp_req_arp->ptype[0] = 0x08;
  arp_req_arp->ptype[1] = 0x00;
  arp_req_arp->hlen[0] = 0x06;
  arp_req_arp->plen[0] = 0x04;

  // Operation is request
  arp_req_arp->oper[0] = 0x00;
  arp_req_arp->oper[1] = 0x01;

  // Set source hardware address
  memcpy(arp_req_arp->sha, own_mac, 6);

  // Set source protocol address
  memcpy(arp_req_arp->spa, own_ip, 4);
}

//=============================================================================
// Sends a wake-on-LAN frame for the specified MAC address
//=============================================================================
void send_wol(const unsigned char* const mac_address)
{
  // Create the buffer in which a WOL frame will be constructed
  unsigned int buf_size = sizeof(ethernet_ii_header) + 102;
  char wol_buffer[buf_size];

  ethernet_ii_header* eth_hdr = (ethernet_ii_header*)wol_buffer;

  // Fill out Ethernet header
  memcpy(eth_hdr->mac_source, own_mac, 6);
  memset(eth_hdr->mac_destination, 0xff, 6);
  eth_hdr->ethertype[0] = 0x08;
  eth_hdr->ethertype[1] = 0x42;

  char* wol_payload = wol_buffer + sizeof(ethernet_ii_header);

  // Add 6 bytes of 0xff
  memset(wol_payload, 0xff, 6);

  // Add 16 repetitions of the MAC address to wake
  for (unsigned int i = 1; i <= 16; i++)
  {
    memcpy(wol_payload + 6 * i, mac_address, 6);
  }

  // The WOL frame is complete; send it
  LinuxRawSocket raw_socket;
  raw_socket.setOutputInterface(interface_name);
  raw_socket.write(const_cast<const char*>(wol_buffer), buf_size);
}

//=============================================================================
// Calls send_wol to wake a device, if enough time has passed since the last WOL
// was sent; ASSUMES THE DEVICE ASSOCIATED WITH THE GIVEN DEVICE INDEX IS LOCKED
//=============================================================================
void wake_device(const unsigned int         device_index,
                 const unsigned char* const requester_mac,
                 const unsigned char* const requester_ip)
{
  // Obtain current time
  time_t current_time = time(0);

  // Issue another WOL if it's been a second or more since the last WOL
  if (current_time - devices[device_index].last_wol_timestamp >= 1)
  {
    // Log the fact that we're going to issue a WOL
    log_issuing_wol(devices[device_index].mac_address,
                    devices[device_index].ip_address,
                    requester_mac,
                    requester_ip);

    // Send the WOL
    send_wol(devices[device_index].mac_address);

    // Save current time as the last time a WOL was sent
    devices[device_index].last_wol_timestamp = current_time;
  }
}

//=============================================================================
// Sends a gratuitous ARP for the specified IP address/MAC address combo
//=============================================================================
void send_garp(const unsigned char* ip_address,
               const unsigned char* mac_address)
{
  // Allocate a buffer for the ARP
  unsigned int buf_size = sizeof(ethernet_ii_header) + sizeof(arp_ipv4);
  char garp_buffer[buf_size];

  ethernet_ii_header* eth_hdr = (ethernet_ii_header*)garp_buffer;

  // Fill out Ethernet header
  memcpy(eth_hdr->mac_source, own_mac, 6);
  memset(eth_hdr->mac_destination, 0xff, 6);
  eth_hdr->ethertype[0] = 0x08;
  eth_hdr->ethertype[1] = 0x06;

  arp_ipv4* arp_hdr = (arp_ipv4*)(garp_buffer + sizeof(ethernet_ii_header));

  // Fill out ARP information
  arp_hdr->htype[0] = 0x00;
  arp_hdr->htype[1] = 0x01;

  arp_hdr->ptype[0] = 0x08;
  arp_hdr->ptype[1] = 0x00;

  arp_hdr->hlen[0] = 0x06;
  arp_hdr->plen[0] = 0x04;

  arp_hdr->oper[0] = 0x00;
  arp_hdr->oper[1] = 0x02;

  memcpy(arp_hdr->sha, mac_address, 6);
  memcpy(arp_hdr->tha, mac_address, 6);

  memcpy(arp_hdr->spa, ip_address, 4);
  memcpy(arp_hdr->tpa, ip_address, 4);

  // The ARP is complete; send it
  LinuxRawSocket raw_socket;
  raw_socket.setOutputInterface(interface_name);
  raw_socket.write(const_cast<const char*>(garp_buffer), buf_size);
}

//=============================================================================
// Sends a gratuitous ARP associating a MAC address with an IP address, if
// enough time has passed since the last one; ASSUMES THE DEVICE ASSOCIATED WITH
// THE GIVEN MAC ADDRESS IS LOCKED
//=============================================================================
void restore_arp_tables(const unsigned int         device_index,
                        const unsigned char* const traffic_mac = 0)
{
  // Obtain current time
  time_t current_time = time(0);

  // Issue another gratuitous ARP if it's been a second or more since the last
  // one
  if (current_time - devices[device_index].last_garp_timestamp >= 1)
  {
    // Log the fact that we're going to issue a gratuitous ARP
    log_issuing_garp(devices[device_index].ip_address,
                     devices[device_index].mac_address,
                     traffic_mac);

    // Send the gratuitous ARP
    send_garp(devices[device_index].ip_address,
              devices[device_index].mac_address);

    // Save current time as the last time  sent
    devices[device_index].last_garp_timestamp = current_time;
  }
}

//=============================================================================
// Called to parse and respond to sniffed frames
//=============================================================================
void handle_frame(const char* frame_buffer, unsigned int bytes_read)
{
  // There are currently two types of interesting traffic; ARP queries and IPv4
  // packets.  Later we will see if this frame contains either of those things.
  // Assume Ethernet II frames.

  // Interpret this frame as an Ethernet II frame
  ethernet_ii_header* eth_frame  = (ethernet_ii_header*)frame_buffer;


  // Drop this frame if it came from the interface the proxy device is using (if
  // it came from ourselves).  Clearly we're not interested in these.
  if (memcmp((void*)eth_frame->mac_source, own_mac, 6) == 0)
  {
    return;
  }


  // First, check the source of the frame.  If it came from from a device
  // thought to be sleeping, change it's status to non-sleeping.
  for (unsigned int i = 0; i < devices.size(); i++)
  {
    if (memcmp((void*)devices[i].mac_address,
               (void*)(frame_buffer + 6),
               6) == 0)
    {
      // If this device is marked as sleeping, update the network's ARP tables
      // so traffic gets send directly to it now, rather than to the proxy; the
      // device is awake so it should handle its own traffic
      if (devices[i].is_sleeping)
      {
        // Device has just been detected to be awake, log this status change
        log_device_awake(devices[i].ip_address, devices[i].mac_address);

        restore_arp_tables(i);
      }

      // This device can't be sleeping, because we just got a frame from it.
      // Change status to reflect this.
      devices[i].is_sleeping = false;

      // Mark device as awake for the sleep checker thread
      devices[i].is_awake = true;
    }
  }


  // Initially interpret frame's contents as an IPv4 ARP packet; later different
  // re-interpretations may be applied as necessary
  arp_ipv4* arp_packet = (arp_ipv4*)(frame_buffer + sizeof(ethernet_ii_header));

  // Ethertype for IPv4 packets
  char ipv4_type[2];
  ipv4_type[0] = 0x08;
  ipv4_type[1] = 0x00;

  // Ethertype for ARP messages
  char arp_type[2];
  arp_type[0] = 0x08;
  arp_type[1] = 0x06;

  // ARP query operation code
  char arp_op_type = 0x01;

  // Does this frame contain an ARP query?
  if (memcmp((void*)eth_frame->ethertype, (void*)arp_type, 2) == 0  &&
      memcmp((void*)&arp_packet->oper[1], (void*)&arp_op_type, 1) == 0)
  {
    // Is this query for a sleeping device this program is proxying for?
    for(unsigned int i = 0; i < devices.size(); i++)
    {
      // Check the IP address this query is for against the stored IP addressess
      // of all tracked devices
      if (memcmp((void*)arp_packet->tpa,
                 (void*)devices[i].ip_address,
                 4) == 0 &&
          devices[i].is_sleeping)
      {
        // ARP query received for a sleeping device this program is proxying
        // for.  Send an ARP response causing the sender to direct traffic here

        // Set up the buffer and establish some easy references into it
        unsigned int buf_size = sizeof(ethernet_ii_header) + sizeof(arp_ipv4);
        char response_buffer[buf_size];

        ethernet_ii_header* response_eth_hdr =
          (ethernet_ii_header*)response_buffer;
        arp_ipv4* response_arp_hdr =
          (arp_ipv4*)((char*)response_buffer + sizeof(ethernet_ii_header));

        // Fill in Ethernet header
        memcpy(response_eth_hdr->mac_destination, eth_frame->mac_source, 6);
        memcpy(response_eth_hdr->mac_source, own_mac, 6);
        memcpy(response_eth_hdr->ethertype, arp_type, 2);

        // Fill in the ARP packet
        response_arp_hdr->htype[0] = 0x00;
        response_arp_hdr->htype[1] = 0x01;
        memcpy(response_arp_hdr->ptype, ipv4_type, 2);
        response_arp_hdr->hlen[0] = 0x06;
        response_arp_hdr->plen[0] = 0x04;
        response_arp_hdr->oper[0] = 0x00;
        response_arp_hdr->oper[1] = 0x02;
        memcpy(response_arp_hdr->sha, own_mac, 6);
        memcpy(response_arp_hdr->spa, arp_packet->tpa, 4);
        memcpy(response_arp_hdr->tha, arp_packet->sha, 6);
        memcpy(response_arp_hdr->tpa, arp_packet->spa, 4);

        // Issue the response; this should cause the computer that queried for
        // the sleeping device to believe this computer IS the sleeping device
        LinuxRawSocket raw_socket;
        raw_socket.setOutputInterface(interface_name);
        raw_socket.write(response_buffer, buf_size);
      }
    }
  }
  // Does this frame contain an IPv4 packet?
  else if (memcmp(eth_frame->ethertype, (void*)ipv4_type, 2) == 0)
  {
    // Consider this packet as an IPv4 packet
    ipv4_header* ipv4_hdr =
      (ipv4_header*)(frame_buffer + sizeof(ethernet_ii_header));

    // Is this packet for a device this proxy is monitoring?
    for(unsigned int i = 0; i < devices.size(); i++)
    {
      // Compare to current device
      if (memcmp(ipv4_hdr->destination_ip, devices[i].ip_address, 4) == 0)
      {
        // Is the device sleeping?
        if (devices[i].is_sleeping)
        {
          // We've intercepted traffic for a sleeping device.  Now it needs to
          // be determined if this traffic is important.

          // Consider only TCP and UDP
          if (*ipv4_hdr->protocol == 0x06 || *ipv4_hdr->protocol == 0x11)
          {
            // If this device has no important ports listed, wake it for any
            // traffic
            if (devices[i].ports.size() == 0)
            {
              wake_device(i,
                          eth_frame->mac_source,
                          (unsigned char*)ipv4_hdr->source_ip);
            }
            else
            {
              // Figure out how long the header in this IPv4 packet is; we have
              // to do this to know where the payload starts, to know where to
              // pick the destination port from

              // The header length in the packet indicates the number of 32-bit
              // words, so the multiply by 4 is necessary to convert to bytes
              unsigned short ipv4_headerlen =
                (*(ipv4_hdr->version_headerlen) & 0x0f) * 4;

              // Save a pointer to the start of the IPv4 payload
              const unsigned char* ipv4_payload =
                reinterpret_cast<const unsigned char*>(
                  frame_buffer + sizeof(ethernet_ii_header) + ipv4_headerlen);

              // Extract the destination port
              unsigned short destination_port =
                *(unsigned short*)(ipv4_payload + 2);

              // Byte-swap the retrieved port if the endian-ness of this host
              // doesn't match network byte order
              if(!is_big_endian)
              {
                // Copy the port's two bytes
                unsigned char byte1 = *(unsigned char*)&destination_port;
                unsigned char byte2 = *((unsigned char*)&destination_port + 1);

                // Copy the two bytes back in, in reverse order
                memcpy((unsigned char*)&destination_port,     &byte2, 1);
                memcpy((unsigned char*)&destination_port + 1, &byte1, 1);
              }

              // Loop over all this device's listed important ports, seeing if
              // any of them match the port to which this packet is destined
              for (std::vector<unsigned short>::iterator iter =
                     devices[i].ports.begin();
                   iter != devices[i].ports.end();
                   iter++)
              {
                // If the packet is destined for an important port, wake the
                // device
                if (*iter == destination_port)
                {
                  wake_device(i,
                              eth_frame->mac_source,
                              (unsigned char*)ipv4_hdr->source_ip);
                  break;
                }
              }
            }
          }
        }
        else
        {
          // We've intercepted traffic for a device that is awake.  This means
          // the device that sent this traffic still believes it should send
          // data to the proxy, when it should be sending data to its intended
          // destination.  Attempt to remedy this situation by broadcasting a
          // gratuitous ARP that should inform the sender of who they should
          // really be sending to.
          restore_arp_tables(i, eth_frame->mac_source);
        }
      }
    }
  }
}

//=============================================================================
// Sets the sleep status of all monitored devices based on how they've responded
// to prior sleep checks
//=============================================================================
void set_sleep_status()
{
  // See which devices have yet to respond.  The ones that haven't responded are
  // deemed asleep.

  // Check all devices
  for(unsigned int i = 0; i < devices.size(); i++)
  {
    // Did this device just fall asleep?
    if (!devices[i].is_sleeping && !devices[i].is_awake)
    {
      // Log the fact that this device has fallen asleep
      log_device_asleep(devices[i].ip_address, devices[i].mac_address);

      // Since this device is now asleep, this proxy should intercept all
      // traffic bound for it.  To accomplish this, a single gratuitous ARP
      // associating this proxy device's MAC with the IP address of the device
      // that has just fallen asleep can be issued.
      if (aggressive_garp)
      {
        log_issuing_garp(devices[i].ip_address, (const unsigned char*)own_mac);
        send_garp(devices[i].ip_address, (const unsigned char*)own_mac);
      }
    }

    // Record the current sleep state
    devices[i].is_sleeping = !devices[i].is_awake;
  }
}

//=============================================================================
// Issues sleep check messages for all monitored devices
//=============================================================================
void issue_sleep_checks()
{
  // Create a socket to issue requests
  LinuxRawSocket query_socket;
  query_socket.setOutputInterface(interface_name);

  // Get a pointer to the ARP section of the request
  arp_ipv4* arp_req_arp =
    (arp_ipv4*)(arp_request + sizeof(ethernet_ii_header));

  // ARP request to all devices
  for(unsigned int i = 0; i < devices.size(); i++)
  {
    // Mark the device as not awake; if it really is awake, the other thread
    // will receive a response to the coming ARP request and mark it as such
    devices[i].is_awake = false;

    // Update buffer with current device's IP and MAC
    memcpy(arp_req_arp->tha, devices[i].mac_address, 6);
    memcpy(arp_req_arp->tpa, devices[i].ip_address,  4);

    // Issue the request
    query_socket.write((const char*)arp_request,
                       sizeof(ethernet_ii_header) + sizeof(arp_ipv4));
  }
}

//=============================================================================
// Program entry point
//=============================================================================
int main(int argc, char** argv)
{
  // Attach clean_exit to the interrupt signal; users can hit Ctrl+c and stop
  // the program
  if (signal(SIGINT, clean_exit) == SIG_ERR)
  {
    fprintf(stderr, "Could not attach SIGINT handler\n");
    return 1;
  }

  // Attach clean_exit to the terminate signal; kill should work with no
  // arguments
  if (signal(SIGTERM, clean_exit) == SIG_ERR)
  {
    fprintf(stderr, "Could not attach SIGTERM handler\n");
    return 1;
  }

  // Read configuration settings
  parse_default_file(default_filename);

  // Process arguments
  if (!process_arguments(argc, argv))
  {
    // TODO: show a help message here
    exit(1);
  }

  // If this process is to daemonize then do it
  if (daemonize)
  {
    if (daemon(0, 0) != 0)
    {
      exit(1);
    }
  }

  // Write our PID to file
  write_pid_to_file(pid_filename);

  // Initialize the list of devices we'll be proxying for
  parse_config_file(config_filename);

  // Initialize the output stream to be used for log file writing
  std::ofstream log_stream(log_filename.c_str(), std::ofstream::app);
  log.setOutputStream(log_stream);
  log.flushAfterWrite(true);
  log.useLocalTime();

  // For some of the things this proxy will do, it needs to know the MAC address
  // and IP address of the interface it will be using.  Obtain this information
  // here.
  obtain_own_mac_and_ip();

  // Determine endian-ness of this host
  unsigned short test_var = 0xff00;
  is_big_endian = *(unsigned char*)&test_var > 0;

  // Initialize the template ARP request used during sleep checking
  initialize_arp_request();

  // Create the socket that will sniff frames
  LinuxRawSocket sniff_socket;
  sniff_socket.setInputInterface(interface_name);
  sniff_socket.enableBlocking();
  sniff_socket.setBlockingTimeout(0.1);

  // Initialize some time-related variables used in the main loop to determine
  // when sleep checks are performed.  These are all initialized to the current
  // time, since there's no better time to initialize them to, and it makes the
  // main loop below work on the first pass

  // Marks the last time a sleep check was performed
  timeval last_sleep_check;
  last_sleep_check.tv_sec  = 0;
  last_sleep_check.tv_usec = 0;

  // Marks the current time
  timeval current_time;
  gettimeofday(&current_time, 0);

  // Tracks the amount of time that's passed since the last sleep check
  double time_waiting = 0.0;

  // True when a sleep check is in progress.
  bool sleep_check_in_progress = false;

  // Stores how many bytes were read from sniff_socket each sniff
  int bytes_read = 0;

  // Sniffed frames are read into this buffer
  char frame_buffer[ETH_FRAME_LEN];

  // Note that the service has started
  log.write("Service starting");

  // The service is not intended to stop
  while(1)
  {
    // Sniff a packet, if any are there
    bytes_read = sniff_socket.read(frame_buffer, ETH_FRAME_LEN);

    // If anything was sniffed, handle it
    if (bytes_read > 0)
    {
      handle_frame(frame_buffer, bytes_read);
    }

    // Get the current time
    gettimeofday(&current_time, 0);

    // How much time has passed since the last sleep check?
    time_waiting = get_time(current_time) - get_time(last_sleep_check);

    // Is it time to perform another sleep check?
    if (time_waiting > device_check_period)
    {
      // Save this time as the last time a sleep check was done
      memcpy(&last_sleep_check, &current_time, sizeof(timeval));

      // We are now checking for sleep, so reset time_waiting
      time_waiting = 0.0;

      // Issue the messages checking all monitored devices for sleep status
      issue_sleep_checks();

      // Note that a sleep check is in progress
      sleep_check_in_progress = true;
    }

    // Is it time to see if devices have responded to the sleep check?
    if (sleep_check_in_progress && time_waiting > device_response_grace_period)
    {
      // Set the sleep status of all monitored devices
      set_sleep_status();

      // Execution of this if ends the sleep check
      sleep_check_in_progress = false;
    }
  }

  clean_exit(0);

  return 1;
}
