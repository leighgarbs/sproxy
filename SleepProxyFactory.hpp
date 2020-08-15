#if !defined SLEEP_PROXY_FACTORY_HPP
#define SLEEP_PROXY_FACTORY_HPP

#include <chrono>

class SleepProxyImpl;
class PosixTimespec;

// Provides a platform-independent way of acquiring platform-specific signal managers.
class SleepProxyFactory
{
public:

    // The interface through which platform-specific signal managers are acquired.
    static SleepProxyImpl* createSleepProxy(
        int                             argc,
        char**                          argv,
        const std::chrono::nanoseconds& period,
        const std::chrono::nanoseconds& tolerance =
        std::chrono::nanoseconds(static_cast<unsigned int>(1e8)));

private:

    // Disallowed, only static functions here
    SleepProxyFactory();
    ~SleepProxyFactory();

    SleepProxyFactory(const SleepProxyFactory&);
    SleepProxyFactory& operator=(const SleepProxyFactory&);
};

#endif
