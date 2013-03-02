// Logging functionality for sleep proxy
// Leigh Garbs

#include "logging.hpp"

#include <cstring>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/time.h> // Linux-specific

#include "sproxy.hpp"

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
// Prints message to standard out (or standard error if is_error), prepended
// with info useful for logging
//=============================================================================
void write_log(const std::string& message, bool is_error = false)
{
  // Will be filled in with string timestamp
  std::string ts_str;

  // Get numeric timestamp
  timeval ts;
  if (gettimeofday(&ts, 0) == -1)
  {
    // Could not generate timestamp
    ts_str = "???";
  }
  else
  {
    // Convert ts into string timestamp
    tm* ts_local = localtime(&ts.tv_sec);

    // Format ts_local
    unsigned int max_ts_len = 30;
    char ts_local_temp[max_ts_len];
    strftime(ts_local_temp, max_ts_len, "%a %b %d %Y %X:", ts_local);

    // Save into string timestamp
    ts_str = ts_local_temp;

    // Add microseconds
    std::ostringstream out_stream;
    out_stream.width(6);
    out_stream.fill('0');
    out_stream << ts.tv_usec;
    ts_str += out_stream.str();

    // Add timezone
    strftime(ts_local_temp, max_ts_len, " %Z", ts_local);
    ts_str += ts_local_temp;
  }

  // Put together the final message to output
  std::string message_to_output =
    "[" + ts_str + " " + interface_name + "] " + message + "\n";

  // Actually write the message; normally cout, but errors go to cerr
  if (is_error)
  {
    std::cerr << message_to_output;
    std::cerr.flush();
  }
  else
  {
    std::cout << message_to_output;
    std::cout.flush();
  }
}


// THE FOLLOWING FUNCTIONS DEFINE THE ISSUABLE LOG MESSAGES

//==============================================================================
// Service is starting
//==============================================================================
void log_starting()
{
  write_log("Service starting");
}

//==============================================================================
// Service is stopping
//==============================================================================
void log_stopping()
{
  write_log("Service stopping");
}

//=============================================================================
// Issuing a WOL
//=============================================================================
void log_issuing_wol(const unsigned char* const mac_address,
		     const unsigned char* const requesting_mac)
{
  // Parse target mac into a string
  std::string mac_address_str;
  mac_to_string(mac_address, mac_address_str);

  // Parse requesting mac into a string
  std::string requesting_mac_str;
  mac_to_string(requesting_mac, requesting_mac_str);

  // Issue the log message
  write_log("Issuing WOL for " + mac_address_str +
	    " on behalf of " + requesting_mac_str);
}

//=============================================================================
// Issuing a gratuitous ARP
//=============================================================================
void log_issuing_garp(const unsigned char* const ip_address,
		      const unsigned char* const mac_address,
		      const unsigned char* const traffic_mac)
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
  write_log(message);
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
  write_log("Device " + mac_address_str + " (" + ip_address_str + ") is awake");
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
  write_log("Device " + mac_address_str + " (" + ip_address_str + ") is asleep");
}

//==============================================================================
// Internal error encountered
//==============================================================================
void log_error(const std::string& error_message)
{
  write_log("ERROR - " + error_message, true);
}
