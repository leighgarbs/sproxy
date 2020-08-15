#include <chrono>

#include "SleepProxyFactory.hpp"

#if defined LINUX || MACOS
#include "PosixSleepProxyImpl.hpp"
#include "PosixTimespec.hpp"
#elif defined WINDOWS
#include "NoopSleepProxyImpl.hpp"
#endif

//=============================================================================================
SleepProxyImpl* SleepProxyFactory::createSleepProxy(int                             argc,
                                                    char**                          argv,
                                                    const std::chrono::nanoseconds& period,
                                                    const std::chrono::nanoseconds& tolerance)
{
#if defined LINUX || MACOS
    return new PosixSleepProxyImpl(argc, argv, period, tolerance);
#else
    // Should be replaced with a proper implementation
    return new NoopSleepProxyImpl();
#endif
}
