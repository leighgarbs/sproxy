#include <chrono>

#include "SleepProxyImpl.hpp"

#include "FixedRateProgram.hpp"

//=============================================================================================
SleepProxyImpl::SleepProxyImpl(int                             argc,
                               char**                          argv,
                               const std::chrono::nanoseconds& period,
                               const std::chrono::nanoseconds& tolerance) :
    FixedRateProgram(argc, argv, period, tolerance)
{
}

//=============================================================================================
SleepProxyImpl::~SleepProxyImpl()
{
}
