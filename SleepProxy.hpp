#if !defined SLEEP_PROXY_HPP
#define SLEEP_PROXY_HPP

#include <chrono>
#include <cstdint>

#include "FixedRateProgramInterface.hpp"

class SignalManager;
class SleepProxyImpl;

class SleepProxy : virtual public FixedRateProgramInterface
{
public:

    SleepProxy(int                             argc,
               char**                          argv,
               const std::chrono::nanoseconds& period,
               const std::chrono::nanoseconds& tolerance =
               std::chrono::nanoseconds(static_cast<unsigned int>(1e8)));

    virtual ~SleepProxy();

    // Program
    virtual int run();
    virtual void getName(std::string& name) const;
    virtual void getArguments(std::vector<std::string>& arguments) const;

    // FixedRateProgram
    virtual void step();
    virtual void setPeriod(const std::chrono::nanoseconds& period);
    virtual void getPeriod(std::chrono::nanoseconds& period) const;
    virtual void setTolerance(const std::chrono::nanoseconds& tolerance);
    virtual void getTolerance(std::chrono::nanoseconds& tolerance) const;
    virtual void setTerminate(bool terminate);
    virtual bool getTerminate() const;

protected:

    // Program
    virtual SignalManager* getSignalManager();

private:

    // This function is called on every hunk of data read off of sniff_socket.  Most
    // significant actions occur in here.
    void handleFrame(const std::uint8_t* frame_buffer, unsigned int bytes_read);

    SleepProxyImpl* sleep_proxy_impl;

    SleepProxy(const SleepProxy&);
    SleepProxy& operator=(const SleepProxy&);
};

#endif
