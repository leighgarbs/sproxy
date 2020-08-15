#if !defined POSIX_SLEEP_PROXY_IMPL_HPP
#define POSIX_SLEEP_PROXY_IMPL_HPP

#include <chrono>
#include <fstream>
#include <string>
#include <vector>

#include "SleepProxyImpl.hpp"

#include "Device.hpp"
#include "Ipv4Address.hpp"
#include "Log.hpp"
#include "MacAddress.hpp"
#include "PosixTimespec.hpp"
#include "RawSocket.hpp"
#include "arp_ipv4.h"
#include "ethernet_ii_header.h"
#include "misc.hpp"

// This doesn't compile anywhere but Linux but here are the Linux-specific headers anyway
#if defined LINUX
#include <linux/if_ether.h>
#endif

class PosixSleepProxyImpl : public SleepProxyImpl
{
public:

    PosixSleepProxyImpl(
        int                             argc,
        char**                          argv,
        const std::chrono::nanoseconds& period,
        const std::chrono::nanoseconds& tolerance =
        std::chrono::nanoseconds(static_cast<unsigned int>(1e8)));

    virtual ~PosixSleepProxyImpl();

    virtual void step();

protected:

    // Delivered signals handled here
    virtual void processDeliveredSignals();

private:

    // This function is called on every hunk of data read off of sniff_socket.  Most
    // significant actions occur in here.
    void handleFrame(const unsigned char* frame_buffer,
                     unsigned int         bytes_read);

    // Interprets program arguments and applies corresponding state
    bool processArguments();

    // Opens the log file; used after log rotation and during startup
    void openLog();

    // Closes the log file; used before log rotation and on shutdown
    void closeLog();

    // Frees resources and triggers program shutdown at the end of the current frame
    void shutdown();

    void logIssuingWol(const MacAddress&  mac_address,
                       const Ipv4Address& ip_address,
                       const MacAddress&  requesting_mac,
                       const Ipv4Address& requesting_ip);

    void logIssuingGratuitousArp(const Ipv4Address& ip_address,
                                 const MacAddress&  mac_address,
                                 const MacAddress&  traffic_mac);

    void logDeviceAwake(const Ipv4Address& ip_address, const MacAddress&  mac_address);
    void logDeviceAsleep(const Ipv4Address& ip_address, const MacAddress&  mac_address);

    bool processDefaultFile(const std::string& filename);
    bool processConfigFile(const std::string& filename);

    void initializeArpRequest();

    void sendWol(const MacAddress& mac_address);

    void wakeDevice(const unsigned int device_index,
                    const MacAddress&  requester_mac,
                    const Ipv4Address& requester_ip);

    void sendGratuitousArp(const Ipv4Address& ip_address, const MacAddress&  mac_address);

    void restoreArpTables(const unsigned int device_index, const MacAddress&  traffic_mac);

    void setSleepStatus();

    void issueSleepChecks();

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
    unsigned char frame_buffer[ETHERNET_FRAME_LENGTH];

    // Length of the input buffers used during config and default file parsing
    static const unsigned int PARSING_BUFFER_LENGTH;


    // Stores known devices to monitor
    std::vector<Device> devices;

    // Stores a template ARP request used when checking if monitored hosts are asleep
    unsigned char arp_request[sizeof(ethernet_ii_header) + sizeof(arp_ipv4)];

    // Stores the MAC of the device this proxy is using to monitor network traffic
    MacAddress own_mac;

    // IP address assigned to interface with name interface_name
    Ipv4Address own_ip;

    misc::ByteOrder byte_order;

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
