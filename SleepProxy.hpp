#if !defined SLEEP_PROXY_HPP
#define SLEEP_PROXY_HPP

#include <fstream>
#include <string>
#include <vector>

#include "FixedRateProgram.hpp"

#include "Device.hpp"
#include "Endian.hpp"
#include "Ipv4Address.hpp"
#include "Log.hpp"
#include "MacAddress.hpp"
#include "PosixTimespec.hpp"
#include "RawSocket.hpp"
#include "arp_ipv4.h"
#include "ethernet_ii_header.h"

// This doesn't compile anywhere but Linux but here are the Linux-specific
// headers anyway
#if defined LINUX
#include <linux/if_ether.h>
#endif

class SleepProxy : public FixedRateProgram
{
public:

    // Parses configuration files and command-line arguments, applies
    // corresponding state, prepares raw socket for use; tp is the period
    // between step() executions
    SleepProxy(int argc, char** argv, const PosixTimespec& tp);

    virtual ~SleepProxy();

    // Body of the main loop, executed periodically and indefinitely
    virtual void step();

protected:

    // Delivered signals handled here
    virtual void processDeliveredSignals();

private:

    // Interprets program arguments and applies corresponding state
    bool processArguments();

    // Opens the log file; used after log rotation and during startup
    void openLog();

    // Closes the log file; used before log rotation and on shutdown
    void closeLog();

    // Frees resources and triggers program shutdown at the end of the current
    // frame
    void shutdown();

    void log_issuing_wol(const MacAddress&  mac_address,
                         const Ipv4Address& ip_address,
                         const MacAddress&  requesting_mac,
                         const Ipv4Address& requesting_ip);

    void log_issuing_garp(const Ipv4Address& ip_address,
                          const MacAddress&  mac_address,
                          const MacAddress&  traffic_mac);

    void log_device_awake(const Ipv4Address& ip_address,
                          const MacAddress&  mac_address);

    void log_device_asleep(const Ipv4Address& ip_address,
                           const MacAddress&  mac_address);

    void parse_default_file(const std::string& filename);

    void parse_config_file(const std::string& filename);

    void initialize_arp_request();

    void send_wol(const MacAddress& mac_address);

    void wake_device(const unsigned int device_index,
                     const MacAddress&  requester_mac,
                     const Ipv4Address& requester_ip);

    void send_garp(const Ipv4Address& ip_address,
                   const MacAddress&  mac_address);

    void restore_arp_tables(const unsigned int device_index,
                            const MacAddress&  traffic_mac);

    void handle_frame(const char* frame_buffer, unsigned int bytes_read);

    void set_sleep_status();

    void issue_sleep_checks();

    static void writePidToFile(const std::string& pid_filename);


    RawSocket sniff_socket;

    // Filename of the default settings file, typically located in /etc/default
    std::string default_filename;

    // Filename of the config file, typically located in /etc
    std::string config_filename;

    // Filename of the log file, typically located in /var/log
    std::string log_filename;

    // Filename of the file in which PID is stored
    std::string pid_filename;

    // Name of the interface on which proxying will take place
    std::string interface_name;


    PosixTimespec frame_start;
    PosixTimespec last_sleep_check;
    PosixTimespec sleep_check_period;
    PosixTimespec sleep_check_response_grace_period;

    static const unsigned int ETHERNET_FRAME_LENGTH = 1514;

    // Sniffed frames are read into this buffer
    char frame_buffer[ETHERNET_FRAME_LENGTH];

    // Length of the input buffers used during config and default file parsing
    static const unsigned int PARSING_BUFFER_LENGTH;


    // Stores known devices to monitor
    std::vector<Device> devices;

    // Stores a template ARP request used when checking if monitored hosts are
    // asleep
    char arp_request[sizeof(ethernet_ii_header) + sizeof(arp_ipv4)];

    // Stores the MAC of the device this proxy is using to monitor network
    // traffic
    MacAddress own_mac;

    // IP address assigned to interface with name interface_name
    Ipv4Address own_ip;

    Endian::Endianness endianness;

    // Used to log important sproxy activities
    Log log;

    // Log messages go out on this stream
    std::ofstream log_stream;

    // Whether or not this process should daemonize
    bool daemonize;

    // How long to wait for responses from monitored devices after querying them

    // Aggressively keep the network up to date on changing ARP status?
    bool aggressive_garp;

    // True when a sleep check is in progress.
    bool sleep_check_in_progress;
};

#endif
