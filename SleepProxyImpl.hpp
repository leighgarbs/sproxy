#if !defined SLEEP_PROXY_IMPL_HPP
#define SLEEP_PROXY_IMPL_HPP

#include <chrono>

#include "FixedRateProgram.hpp"

class SleepProxyImpl : public FixedRateProgram
{
public:

    friend class SleepProxy;

    SleepProxyImpl(int                             argc,
                   char**                          argv,
                   const std::chrono::nanoseconds& period,
                   const std::chrono::nanoseconds& tolerance =
                   std::chrono::nanoseconds(static_cast<unsigned int>(1e8)));

    virtual ~SleepProxyImpl();

    // Body of the main loop, executed periodically and indefinitely
    virtual void step() = 0;

private:

    // This function is called on every hunk of data read off of sniff_socket.  Most
    // significant actions occur in here.
    virtual void handleFrame(const unsigned char* frame_buffer,
                             unsigned int         bytes_read) = 0;
};

#endif
