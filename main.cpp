#include <chrono>

#include "SleepProxy.hpp"

int main(int argc, char** argv)
{
    SleepProxy sproxy(argc, argv, std::chrono::milliseconds(100));
    return sproxy.run();
}
