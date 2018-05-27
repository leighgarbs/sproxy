#include <unistd.h>

#include "SleepProxy.hpp"

int main(int argc, char** argv)
{
    SleepProxy sproxy(argc, argv);

    // If this process is to daemonize then do it
    if (daemonize)
    {
        if (daemon(0, 0) != 0)
        {
            exit(1);
        }
    }


    // The service is not intended to stop
    while(1)
    {
        sproxy.step();
    }

    return 1;
}
