#if !defined SLEEP_PROXY_IMPL_HPP
#define SLEEP_PROXY_IMPL_HPP

#include "FixedRateProgram.hpp"

class SleepProxyImpl : public FixedRateProgram
{
public:

    friend class SleepProxy;

    SleepProxyImpl(int argc, char** argv);
    virtual ~SleepProxyImpl();

    // Body of the main loop, executed periodically and indefinitely
    virtual void step() = 0;

private:

    // This function is called on every hunk of data read off of sniff_socket.  Most
    // significant actions occur in here.
    virtual void handleFrame(const unsigned char* frame_buffer, unsigned int bytes_read) = 0;
};

#endif
