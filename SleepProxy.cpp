#include <chrono>
#include <cstdint>
#include <stdexcept>

#include "SleepProxy.hpp"

#include "SleepProxyFactory.hpp"
#include "SleepProxyImpl.hpp"
#include "misc.hpp"

//=============================================================================================
SleepProxy::SleepProxy(int argc, char** argv) :
    sleep_proxy_impl(0)
{
    sleep_proxy_impl = SleepProxyFactory::createSleepProxy(argc, argv);

    if (!sleep_proxy_impl)
    {
        throw std::runtime_error("No SleepProxyImpl available for this platform");
    }
}

//=============================================================================================
SleepProxy::~SleepProxy()
{
    delete sleep_proxy_impl;
}

//=============================================================================================
int SleepProxy::run()
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           return sleep_proxy_impl->run());
}

//=============================================================================================
void SleepProxy::getName(std::string& name) const
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->getName(name));
}

//=============================================================================================
void SleepProxy::getArguments(std::vector<std::string>& arguments) const
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->getArguments(arguments));
}

//=============================================================================================
void SleepProxy::step()
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->step());
}

//=============================================================================================
void SleepProxy::setPeriod(const std::chrono::nanoseconds& period)
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->setPeriod(period));
}

//=============================================================================================
void SleepProxy::getPeriod(std::chrono::nanoseconds& period) const
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->getPeriod(period));
}

//=============================================================================================
void SleepProxy::setTolerance(const std::chrono::nanoseconds& tolerance)
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->setTolerance(tolerance));
}

//=============================================================================================
void SleepProxy::getTolerance(std::chrono::nanoseconds& tolerance) const
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->getTolerance(tolerance));
}

//=============================================================================================
void SleepProxy::setTerminate(bool terminate)
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->setTerminate(terminate));
}

//=============================================================================================
bool SleepProxy::getTerminate() const
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           return sleep_proxy_impl->getTerminate());
}

//=============================================================================================
SignalManager* SleepProxy::getSignalManager()
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           return sleep_proxy_impl->getSignalManager());
}

//=============================================================================================
void SleepProxy::handleFrame(const std::uint8_t* frame_buffer,
                             unsigned int        bytes_read)
{
    IF_NULL_THROW_ELSE_RUN(sleep_proxy_impl,
                           "No SleepProxyImpl available for this platform",
                           sleep_proxy_impl->handleFrame(frame_buffer, bytes_read));
}
