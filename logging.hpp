// Sleep proxy logging functionality
// Leigh Garbs

#if !defined LOGGING_HPP
#define LOGGING_HPP

#include <string>

void log_starting();
void log_stopping();

void log_issuing_wol(const unsigned char* const target_mac,
		     const unsigned char* const requesting_mac);

void log_issuing_garp(const unsigned char* const ip_address,
		      const unsigned char* const mac_address,
		      const unsigned char* const traffic_mac = 0);

void log_device_awake(const unsigned char* const ip_address,
		      const unsigned char* const mac_address);

void log_device_asleep(const unsigned char* const ip_address,
		       const unsigned char* const mac_address);

void log_error(const std::string& error_message);

#endif
