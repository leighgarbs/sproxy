#if !defined SLEEP_PROXY_HPP
#define SLEEP_PROXY_HPP

#include <fstream>
#include <string>
#include <vector>

#include "FixedRateProgram.hpp"

#include "Device.hpp"
#include "Log.hpp"
#include "PosixTimespec.hpp"
#include "arp_ipv4.h"
#include "ethernet_ii_header.h"

// This doesn't compile anywhere but Linux but here are the Linux-specific
// headers anyway
#if defined LINUX
#include <linux/if_ether.h>
#include "LinuxRawSocket.hpp"
#endif

class SleepProxy : public FixedRateProgram
{
public:

    SleepProxy(int argc, char** argv, const PosixTimespec& tp);

    virtual ~SleepProxy();

    virtual void step();

    // Signal event handlers
    virtual int signal(int sig);

private:

    void closeLog();

    void openLog();

    void cleanExit();

    void writePidToFile(const std::string& pid_filename);

    bool processArguments();

    void obtain_own_mac_and_ip();

    double get_time(const timeval& time);

    void mac_to_string(const unsigned char* const mac,
                       std::string&               mac_str);

    void ip_to_string(const unsigned char* const ip,
                      std::string&               ip_str);

    void log_issuing_wol(const unsigned char* const mac_address,
                         const unsigned char* const ip_address,
                         const unsigned char* const requesting_mac,
                         const unsigned char* const requesting_ip);

    void log_issuing_garp(const unsigned char* const ip_address,
                          const unsigned char* const mac_address,
                          const unsigned char* const traffic_mac = 0);

    void log_device_awake(const unsigned char* const ip_address,
                          const unsigned char* const mac_address);

    void log_device_asleep(const unsigned char* const ip_address,
                           const unsigned char* const mac_address);

    void parse_default_file(const std::string& filename);

    void parse_config_file(const std::string& filename);

    void initialize_arp_request();

    void send_wol(const unsigned char* const mac_address);

    void wake_device(const unsigned int         device_index,
                     const unsigned char* const requester_mac,
                     const unsigned char* const requester_ip);

    void send_garp(const unsigned char* ip_address,
                   const unsigned char* mac_address);

    void restore_arp_tables(const unsigned int         device_index,
                            const unsigned char* const traffic_mac = 0);

    void handle_frame(const char* frame_buffer, unsigned int bytes_read);

    void set_sleep_status();

    void issue_sleep_checks();


    LinuxRawSocket sniff_socket;

    PosixTimespec frame_start;
    PosixTimespec last_sleep_check;

    // Sniffed frames are read into this buffer
    char frame_buffer[ETH_FRAME_LEN];

    // Length of the input buffers used during config and default file parsing
    static const unsigned int PARSING_BUFFER_LENGTH;

    // Filename of the default settings file, typically located in /etc/default
    std::string default_filename;

    // Stores known devices to monitor
    std::vector<Device> devices;

    // Stores a template ARP request used when checking if monitored hosts are
    // asleep
    char arp_request[sizeof(ethernet_ii_header) + sizeof(arp_ipv4)];

    // Stores the MAC of the device this proxy is using to monitor network
    // traffic
    char own_mac[6];

    // IP address assigned to interface with name interface_name
    char own_ip[4];

    // Is this host big-endian?
    bool is_big_endian;

    // Used to log important sproxy activities
    Log log;

    // Log messages go out on this stream
    std::ofstream log_stream;

    // THESE CONFIGURATION VARIABLES ARE SET BASED ON THE DEFAULT FILE AND/OR
    // PROGRAM ARGUMENTS

    // Name of the interface on which proxying will take place
    std::string interface_name;

    // Filename of the config file, typically located in /etc
    std::string config_filename;

    // Filename of the log file, typically located in /var/log
    std::string log_filename;

    // Filename of the file in which PID is stored
    std::string pid_filename;

    // Whether or not this process should daemonize
    bool daemonize;

    // Length of time between device checks
    unsigned int device_check_period;

    // How long to wait for responses from monitored devices after querying them
    unsigned int device_response_grace_period;

    // Aggressively keep the network up to date on changing ARP status?
    bool aggressive_garp;

    // True when a sleep check is in progress.
    bool sleep_check_in_progress;
};

#endif
