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
#include <iterator>
#include <net/if.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <vector>

#include "SleepProxy.hpp"

#include "Endian.hpp"
#include "Ipv4Address.hpp"
#include "Log.hpp"
#include "MacAddress.hpp"
#include "PosixTimespec.hpp"
#include "RawSocket.hpp"
#include "arp_ipv4.h"
#include "ethernet_ii_header.h"
#include "ipv4_header.h"
#include "miscNetworking.hpp"
#include "tcp_header.h"

const unsigned int SleepProxy::PARSING_BUFFER_LENGTH = 1000;

//==============================================================================
// Parses configuration files and command-line arguments, applies corresponding
// state, prepares raw socket for use; tp is the period between step()
// executions
//=============================================================================
SleepProxy::SleepProxy(int argc, char** argv, const PosixTimespec& tp) :
    FixedRateProgram(argc, argv, tp),
    default_filename("/etc/sproxy/config"),
    config_filename("/etc/sproxy/devices"),
    log_filename("/var/log/sproxy.log"),
    pid_filename("/var/run/sproxy.pid"),
    interface_name("eth0"),
    sleep_check_period(10),
    sleep_check_response_grace_period(1),
    endianness(Endian::LITTLE),
    daemonize(false),
    aggressive_garp(true),
    sleep_check_in_progress(false)
{
    // Read configuration settings
    parse_default_file(default_filename);

    // Process arguments
    if (!processArguments())
    {
        // TODO: show a help message here
        exit(1);
    }

    // Write our PID to file
    writePidToFile(pid_filename);

    // Initialize the list of devices we'll be proxying for
    parse_config_file(config_filename);

    // Initialize the output stream to be used for log file writing
    openLog();

    // For some of the things this proxy will do, it needs to know the MAC
    // address and IP address of the interface it will be using.  Obtain this
    // information here.
    miscNetworking::getMacAddress(interface_name,  own_mac);
    miscNetworking::getIpv4Address(interface_name, own_ip);

    // Determine endian-ness of this host
    endianness = Endian::getEndianness();

    // Initialize the template ARP request used during sleep checking
    initialize_arp_request();

    // Create the socket that will sniff frames
    sniff_socket.setInputInterface(interface_name);
    sniff_socket.disableBlocking();

    // Note that the service has started
    log.write("Service starting");
}

//==============================================================================
SleepProxy::~SleepProxy()
{
    shutdown();
}

//==============================================================================
// Body of the main loop, executed periodically and indefinitely
//==============================================================================
void SleepProxy::step()
{
    // Grab the current time
    getFrameStart(frame_start);

    // How much time has passed since the last sleep check?
    PosixTimespec time_since_lsc = frame_start - last_sleep_check;

    // Is it time to perform another sleep check?
    if (time_since_lsc >= sleep_check_period)
    {
        // Okay, we need to do a sleep check then

        // Reset sleep check timers
        last_sleep_check = frame_start;
        time_since_lsc = 0;

        // Note that a sleep check is in progress
        sleep_check_in_progress = true;

        // Issue the messages checking all monitored devices for sleep status
        issue_sleep_checks();
    }

    // Is it time to see if devices have responded to the sleep check?
    if (sleep_check_in_progress &&
        time_since_lsc > sleep_check_response_grace_period)
    {
        // Set the sleep status of all monitored devices
        set_sleep_status();

        // Sleep check is over
        sleep_check_in_progress = false;
    }

    int bytes_read = 0;
    do
    {
        // Try to sniff a frame
        bytes_read = sniff_socket.read(frame_buffer, ETHERNET_FRAME_LENGTH);

        // If anything was sniffed, handle it
        if (bytes_read > 0)
        {
            handle_frame(frame_buffer, bytes_read);
        }
    }
    while (bytes_read > 0);

    // It's possible for this to run shutdown(), which itself releases resources
    // needed by this class.  Let's handle signals here, so if we do indeed
    // shutdown we do so after this frame has used all the needed resources.
    processDeliveredSignals();
}

//==============================================================================
// Delivered signals handled here
//==============================================================================
void SleepProxy::processDeliveredSignals()
{
    if (isSignalDelivered(SIGUSR1))
    {
        // Logrotate uses this
        closeLog();
    }

    if (isSignalDelivered(SIGUSR2))
    {
        // Logrotate uses this
        openLog();
    }

    if (isSignalDelivered(SIGINT) || isSignalDelivered(SIGTERM))
    {
        shutdown();
    }

    unsignalAll();
}

//==============================================================================
// Interprets program arguments and applies corresponding state
//==============================================================================
bool SleepProxy::processArguments()
{
    std::vector<std::string> arguments;
    getArguments(arguments);

    for (std::vector<std::string>::iterator carg = arguments.begin();
         carg != arguments.end();
         ++carg)
    {
        // Argument -D indicates this process should daemonize itself
        if (*carg == "-D")
        {
            daemonize = true;
        }
        // Process argument pairs here
        else if (std::distance(carg, arguments.end()) > 1)
        {
            // Convenience reference to the second argument in the pair
            std::vector<std::string>::iterator narg = carg + 1;

            // Assume we're going to process a valid argument here.  If we don't
            // this will be set false
            bool twoarg_processed = true;

            // Argument -c specifies the config file filename
            if (*carg == "-c")
            {
                config_filename = *narg;
            }
            // Argument -d specifies the default file filename
            else if (*carg == "-d")
            {
                default_filename = *narg;
            }
            // Argument -l specifies the log file filename
            else if (*carg == "-i")
            {
                interface_name = *narg;
            }
            // Argument -l specifies the log file filename
            else if (*carg == "-l")
            {
                log_filename = *narg;
            }
            // Argument --pidfile specifies the file in which the PID is stored
            else if (*carg == "--pidfile")
            {
                pid_filename = *narg;
            }
            else
            {
                // If we get here we didn't actually process anything
                twoarg_processed = false;
            }

            // If we processed a switch with an argument then we should bump the
            // current argument here to prevent the argument from being
            // processed again
            if (twoarg_processed)
            {
                ++carg;
            }
        }
    }

    // If execution reaches here there was an acceptable set of arguments
    // provided
    return true;
}

//==============================================================================
// Opens the log file; used after log rotation and during startup
//==============================================================================
void SleepProxy::openLog()
{
    log_stream.open(log_filename.c_str(), std::ofstream::app);

    log.setOutputStream(log_stream);
    log.flushAfterWrite(true);
    log.useLocalTime();

    log.write("Log file open");
}

//==============================================================================
// Closes the log file; used before log rotation and on shutdown
//==============================================================================
void SleepProxy::closeLog()
{
    log.write("Closing log file");
    log_stream.close();
}

//==============================================================================
// Frees resources and triggers program shutdown at the end of the current frame
//==============================================================================
void SleepProxy::shutdown()
{
    // Log that the service is stopping
    log.write("Service stopping");

    closeLog();

    // Delete the PID file
    unlink(pid_filename.c_str());

    // Signal that we should stop running
    setTerminate(true);
}

//==============================================================================
// Issuing a WOL
//==============================================================================
void SleepProxy::log_issuing_wol(const MacAddress&  mac_address,
                                 const Ipv4Address& ip_address,
                                 const MacAddress&  requesting_mac,
                                 const Ipv4Address& requesting_ip)
{
    std::ostringstream outstream;
    outstream << "Issuing WOL for " << mac_address << " (" << ip_address
              << ") on behalf of " << requesting_mac << " (" << requesting_ip
              << ")";

    log.write(outstream.str());
}

//==============================================================================
// Issuing a gratuitous ARP
//==============================================================================
void SleepProxy::log_issuing_garp(const Ipv4Address& ip_address,
                                  const MacAddress&  mac_address,
                                  const MacAddress&  traffic_mac)
{
    std::ostringstream outstream;
    outstream << "Issuing gratuitous ARP associating " << ip_address
              << " with ";

    // See if the MAC address we're dealing with is the proxy's MAC address, and
    // if it is, we'll print 'self' in the log in place of the proxy's MAC,
    // because this is easier to understand
    if (own_mac == mac_address)
    {
        outstream << "self";
    }
    else
    {
        outstream << mac_address;
    }

    // Define message now, may be appended to later

    // If a traffic mac was given, incorporate that into the log message
    /*if (traffic_mac)
    {
        // Parse traffic mac into a string
        std::string traffic_mac_str;
        mac_to_string(traffic_mac, traffic_mac_str);

        // Append to previously defined message
        message += " on behalf of " + traffic_mac_str;
        }*/

    // Issue the log message
    log.write(outstream.str());
}

//==============================================================================
// Device has awoken
//==============================================================================
void SleepProxy::log_device_awake(const Ipv4Address& ip_address,
                                  const MacAddress&  mac_address)
{
    std::ostringstream message_stream;
    message_stream << "Device " << mac_address << " (" << ip_address
                   << ") is awake";

    log.write(message_stream.str());
}

//==============================================================================
// Device has fallen asleep
//==============================================================================
void SleepProxy::log_device_asleep(const Ipv4Address& ip_address,
                                   const MacAddress&  mac_address)
{
    std::ostringstream message_stream;
    message_stream << "Device " << mac_address << " (" << ip_address
                   << ") is asleep";

    log.write(message_stream.str());
}

//==============================================================================
// Parses sproxy defaults file
//==============================================================================
void SleepProxy::parse_default_file(const std::string& filename)
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

        // If there isn't an equal sign, or the equal sign is at the beginning
        // or end of the buffer, just go to the next line because this line is
        // bad
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
        else if (left_side == "SLEEP_CHECK_PERIOD")
        {
            // Convert the right side to a number, that's what it's supposed to
            // be
            convert_to_number.clear();
            convert_to_number.str(right_side);
            convert_to_number >> sleep_check_period;
        }
        else if (left_side == "SLEEP_CHECK_RESPONSE_GRACE_PERIOD")
        {
            convert_to_number.clear();
            convert_to_number.str(right_side);
            convert_to_number >> sleep_check_response_grace_period;
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

//==============================================================================
// Parses sproxy config file
//==============================================================================
void SleepProxy::parse_config_file(const std::string& filename)
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

        // If we just read a properly formatted MAC address, the token's length
        // will be 12 characters (2 for each byte) plus 5 colons
        if (token.size() != 17)
        {
            // If the MAC parsing failed, tell the user why and exit
            std::cerr << "Error in " << filename << "\n"
                      << "Could not parse MAC address on line " << line_number
                      << "\n";
            shutdown();
        }

        // Now that we know we have a new device to monitor, push a new Device
        // onto the list of devices to track it
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
            shutdown();
        }

        // Copy from temporary storage into permanent storage
        for (unsigned int i = 0; i < 6; i++)
        {
            devices.back().mac_address[i] =
                static_cast<unsigned char>(temp_mac[i]);
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
            std::cerr << "Could not parse IP address on line " << line_number
                      << "\n";
            shutdown();
        }

        // Copy from temporary storage into permanent storage
        for (unsigned int i = 0; i < 4; i++)
        {
            devices.back().ip_address[i] =
                static_cast<unsigned char>(temp_ip[i]);
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
                std::cerr << "Unable to parse port on line " << line_number
                          << "\n";
                shutdown();
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

//==============================================================================
// Initializes the arp_request global variable with a template ARP request
//==============================================================================
void SleepProxy::initialize_arp_request()
{
    ethernet_ii_header* arp_req_eth_hdr = (ethernet_ii_header*)arp_request;
    arp_ipv4* arp_req_arp =
        (arp_ipv4*)(arp_request + sizeof(ethernet_ii_header));

    // Set destination MAC
    memset(arp_req_eth_hdr->mac_destination, 0xff, 6);

    // Set source MAC
    own_mac.writeRaw(arp_req_eth_hdr->mac_source);

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
    own_mac.writeRaw(arp_req_arp->sha);

    // Set source protocol address
    own_ip.writeRaw(arp_req_arp->spa);
}

//==============================================================================
// Sends a wake-on-LAN frame for the specified MAC address
//==============================================================================
void SleepProxy::send_wol(const MacAddress& mac_address)
{
    // Create the buffer in which a WOL frame will be constructed
    unsigned int buf_size = sizeof(ethernet_ii_header) + 102;
    char wol_buffer[buf_size];

    ethernet_ii_header* eth_hdr = (ethernet_ii_header*)wol_buffer;

    // Fill out Ethernet header
    own_mac.writeRaw(eth_hdr->mac_source);
    memset(eth_hdr->mac_destination, 0xff, 6);
    eth_hdr->ethertype[0] = 0x08;
    eth_hdr->ethertype[1] = 0x42;

    char* wol_payload = wol_buffer + sizeof(ethernet_ii_header);

    // Add 6 bytes of 0xff
    memset(wol_payload, 0xff, 6);

    // Add 16 repetitions of the MAC address to wake
    for (unsigned int i = 1; i <= 16; i++)
    {
        mac_address.writeRaw(wol_payload + 6 * i);
    }

    // The WOL frame is complete; send it
    RawSocket raw_socket;
    raw_socket.setOutputInterface(interface_name);
    raw_socket.write(const_cast<const char*>(wol_buffer), buf_size);
}

//==============================================================================
// Calls send_wol to wake a device, if enough time has passed since the last WOL
// was sent; ASSUMES THE DEVICE ASSOCIATED WITH THE GIVEN DEVICE INDEX IS LOCKED
//==============================================================================
void SleepProxy::wake_device(const unsigned int device_index,
                             const MacAddress&  requester_mac,
                             const Ipv4Address& requester_ip)
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

//==============================================================================
// Sends a gratuitous ARP for the specified IP address/MAC address combo
//==============================================================================
void SleepProxy::send_garp(const Ipv4Address& ip_address,
                           const MacAddress&  mac_address)
{
    // Allocate a buffer for the ARP
    unsigned int buf_size = sizeof(ethernet_ii_header) + sizeof(arp_ipv4);
    char garp_buffer[buf_size];

    ethernet_ii_header* eth_hdr = (ethernet_ii_header*)garp_buffer;

    // Fill out Ethernet header
    own_mac.writeRaw(eth_hdr->mac_source);
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

    mac_address.writeRaw(arp_hdr->sha);
    mac_address.writeRaw(arp_hdr->tha);

    ip_address.writeRaw(arp_hdr->spa);
    ip_address.writeRaw(arp_hdr->tpa);

    // The ARP is complete; send it
    RawSocket raw_socket;
    raw_socket.setOutputInterface(interface_name);
    raw_socket.write(const_cast<const char*>(garp_buffer), buf_size);
}

//==============================================================================
// Sends a gratuitous ARP associating a MAC address with an IP address, if
// enough time has passed since the last one; ASSUMES THE DEVICE ASSOCIATED WITH
// THE GIVEN MAC ADDRESS IS LOCKED
//==============================================================================
void SleepProxy::restore_arp_tables(const unsigned int device_index,
                                    const MacAddress&  traffic_mac)
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

//==============================================================================
// Called to parse and respond to sniffed frames
//==============================================================================
void SleepProxy::handle_frame(const char* frame_buffer, unsigned int bytes_read)
{
    // There are currently two types of interesting traffic; ARP queries and
    // IPv4 packets.  Later we will see if this frame contains either of those
    // things.  Assume Ethernet II frames.

    // Interpret this frame as an Ethernet II frame
    ethernet_ii_header* eth_frame  = (ethernet_ii_header*)frame_buffer;

    // Drop this frame if it came from the interface the proxy device is using
    // (if it came from ourselves).  Clearly we're not interested in these.
    MacAddress mac_source;
    mac_source.readRaw(eth_frame->mac_source);
    if (mac_source == own_mac)
    {
        return;
    }

    // First, check the source of the frame.  If it came from from a device
    // thought to be sleeping, change it's status to non-sleeping.
    for (unsigned int i = 0; i < devices.size(); i++)
    {
        if (devices[i].mac_address == mac_source)
        {
            // If this device is marked as sleeping, update the network's ARP
            // tables so traffic gets send directly to it now, rather than to
            // the proxy; the device is awake so it should handle its own
            // traffic
            if (devices[i].is_sleeping)
            {
                // Device has just been detected to be awake, log this status
                // change
                log_device_awake(devices[i].ip_address, devices[i].mac_address);

                // TODO: re-enable this
                //restore_arp_tables(i);
            }

            // This device can't be sleeping, because we just got a frame from
            // it.  Change status to reflect this.
            devices[i].is_sleeping = false;

            // Mark device as awake for the sleep checker thread
            devices[i].is_awake = true;
        }
    }

    // Initially interpret frame's contents as an IPv4 ARP packet; later
    // different re-interpretations may be applied as necessary
    arp_ipv4* arp_packet = (arp_ipv4*)(frame_buffer +
                                       sizeof(ethernet_ii_header));

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
            // Check the IP address this query is for against the stored IP
            // addresses of all tracked devices
            Ipv4Address tpa;
            tpa.readRaw(arp_packet->tpa);
            if (tpa == devices[i].ip_address)
            {
                // ARP query received for a sleeping device this program is
                // proxying for.  Send an ARP response causing the sender to
                // direct traffic here

                // Set up the buffer and establish some easy references into it
                unsigned int buf_size =
                    sizeof(ethernet_ii_header) + sizeof(arp_ipv4);
                char response_buffer[buf_size];

                ethernet_ii_header* response_eth_hdr =
                    (ethernet_ii_header*)response_buffer;

                arp_ipv4* response_arp_hdr =
                    (arp_ipv4*)((char*)response_buffer +
                                sizeof(ethernet_ii_header));

                // Fill in Ethernet header
                memcpy(response_eth_hdr->mac_destination,
                       eth_frame->mac_source,
                       6);

                own_mac.writeRaw(response_eth_hdr->mac_source);
                memcpy(response_eth_hdr->ethertype, arp_type, 2);

                // Fill in the ARP packet
                response_arp_hdr->htype[0] = 0x00;
                response_arp_hdr->htype[1] = 0x01;
                memcpy(response_arp_hdr->ptype, ipv4_type, 2);
                response_arp_hdr->hlen[0] = 0x06;
                response_arp_hdr->plen[0] = 0x04;
                response_arp_hdr->oper[0] = 0x00;
                response_arp_hdr->oper[1] = 0x02;
                own_mac.writeRaw(response_arp_hdr->sha);
                memcpy(response_arp_hdr->spa, arp_packet->tpa, 4);
                memcpy(response_arp_hdr->tha, arp_packet->sha, 6);
                memcpy(response_arp_hdr->tpa, arp_packet->spa, 4);

                // Issue the response; this should cause the computer that
                // queried for the sleeping device to believe this computer IS
                // the sleeping device
                RawSocket raw_socket;
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
            Ipv4Address destination_ip;
            destination_ip.readRaw(ipv4_hdr->destination_ip);
            if (destination_ip == devices[i].ip_address)
            {
                // Is the device sleeping?
                if (devices[i].is_sleeping)
                {
                    // We've intercepted traffic for a sleeping device.  Now it
                    // needs to be determined if this traffic is important.

                    // Consider only TCP and UDP
                    if (*ipv4_hdr->protocol == 0x06 ||
                        *ipv4_hdr->protocol == 0x11)
                    {
                        // If this device has no important ports listed, wake it
                        // for any traffic
                        if (devices[i].ports.size() == 0)
                        {
                            Ipv4Address source_ip;
                            source_ip.readRaw(ipv4_hdr->source_ip);
                            wake_device(i, mac_source, source_ip);
                        }
                        else
                        {
                            // Figure out how long the header in this IPv4
                            // packet is; we have to do this to know where the
                            // payload starts, to know where to pick the
                            // destination port from

                            // The header length in the packet indicates the
                            // number of 32-bit words, so the multiply by 4 is
                            // necessary to convert to bytes
                            unsigned short ipv4_headerlen =
                                (*(ipv4_hdr->version_headerlen) & 0x0f) * 4;

                            // Save a pointer to the start of the IPv4 payload
                            const unsigned char* ipv4_payload =
                                reinterpret_cast<const unsigned char*>(
                                    frame_buffer + sizeof(ethernet_ii_header) +
                                    ipv4_headerlen);

                            // Extract the destination port
                            unsigned short destination_port =
                                *(unsigned short*)(ipv4_payload + 2);

                            // Byte-swap the retrieved port if the endian-ness
                            // of this host doesn't match network byte order
                            if (endianness == Endian::LITTLE)
                            {
                                // Copy the port's two bytes
                                unsigned char byte1 =
                                    *(unsigned char*)&destination_port;
                                unsigned char byte2 =
                                    *((unsigned char*)&destination_port + 1);

                                // Copy the two bytes back in, in reverse order

                                memcpy((unsigned char*)&destination_port,
                                       &byte2,
                                       1);

                                memcpy((unsigned char*)&destination_port + 1,
                                       &byte1,
                                       1);
                            }

                            // Loop over all this device's listed important
                            // ports, seeing if any of them match the port to
                            // which this packet is destined
                            for (std::vector<unsigned short>::iterator iter =
                                     devices[i].ports.begin();
                                 iter != devices[i].ports.end();
                                 ++iter)
                            {
                                // If the packet is destined for an important
                                // port, wake the device
                                if (*iter == destination_port)
                                {
                                    Ipv4Address source_ip;
                                    source_ip.readRaw(ipv4_hdr->source_ip);
                                    wake_device(i, mac_source, source_ip);

                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    // We've intercepted traffic for a device that is awake.
                    // This means the device that sent this traffic still
                    // believes it should send data to the proxy, when it should
                    // be sending data to its intended destination.  Attempt to
                    // remedy this situation by broadcasting a gratuitous ARP
                    // that should inform the sender of who they should really
                    // be sending to.
                    restore_arp_tables(i, mac_source);
                }
            }
        }
    }
}

//==============================================================================
// Sets the sleep status of all monitored devices based on how they've responded
// to prior sleep checks
//==============================================================================
void SleepProxy::set_sleep_status()
{
    // See which devices have yet to respond.  The ones that haven't responded
    // are deemed asleep.

    // Check all devices
    for(unsigned int i = 0; i < devices.size(); i++)
    {
        // Did this device just fall asleep?
        if (!devices[i].is_sleeping && !devices[i].is_awake)
        {
            // Log the fact that this device has fallen asleep
            log_device_asleep(devices[i].ip_address, devices[i].mac_address);

            // Since this device is now asleep, this proxy should intercept all
            // traffic bound for it.  To accomplish this, a single gratuitous
            // ARP associating this proxy device's MAC with the IP address of
            // the device that has just fallen asleep can be issued.
            if (aggressive_garp)
            {
                // TODO: re-enable this
                //log_issuing_garp(devices[i].ip_address, own_mac);
                send_garp(devices[i].ip_address, own_mac);
            }
        }

        // Record the current sleep state
        devices[i].is_sleeping = !devices[i].is_awake;
    }
}

//==============================================================================
// Issues sleep check messages for all monitored devices
//==============================================================================
void SleepProxy::issue_sleep_checks()
{
    // Create a socket to issue requests
    RawSocket query_socket;
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
        devices[i].mac_address.writeRaw(arp_req_arp->tha);
        devices[i].ip_address.writeRaw(arp_req_arp->tpa);

        // Issue the request
        query_socket.write((const char*)arp_request,
                           sizeof(ethernet_ii_header) + sizeof(arp_ipv4));
    }
}

//==============================================================================
// Writes the PID of the calling process to file
//==============================================================================
void SleepProxy::writePidToFile(const std::string& pid_filename)
{
    std::ofstream out_stream(pid_filename.c_str());
    out_stream << getpid() << "\n";
    out_stream.close();
}
