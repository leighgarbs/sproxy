#include "SleepProxyFactory.hpp"

#if defined LINUX || MACOS
#include "PosixSleepProxyImpl.hpp"
#include "PosixTimespec.hpp"
#elif defined WINDOWS
#include "NoopSleepProxyImpl.hpp"
#endif

//=============================================================================================
SleepProxyImpl* SleepProxyFactory::createSleepProxy(int argc, char** argv)
{
#if defined LINUX || MACOS
    return new PosixSleepProxyImpl(argc, argv);
#else
    // Should be replaced with a proper implementation
    return new NoopSleepProxyImpl();
#endif
}
