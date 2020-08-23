#include <chrono>

#include "SleepProxy.hpp"

int main(int argc, char** argv)
{
    SleepProxy sproxy(argc, argv);
    return sproxy.run();
}
