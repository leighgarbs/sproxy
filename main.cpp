#include "SleepProxy.hpp"

int main(int argc, char** argv)
{
    SleepProxy sproxy;

    // The service is not intended to stop
    while(1)
    {
        sproxy.step();
    }

    return 1;
}
