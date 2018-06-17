#include "SleepProxy.hpp"

SleepProxy* sproxyp = 0;

extern "C" void handle_signal(int sig)
{
    if (sproxyp)
    {
        sproxyp->signal(sig);
    }
}

int main(int argc, char** argv)
{
    // Need to update rate
    SleepProxy sproxy(argc, argv, 0.1);
    sproxyp = &sproxy;

    // Register signals to handle
    sproxy.registerSignal(SIGINT,  handle_signal);
    sproxy.registerSignal(SIGTERM, handle_signal);
    sproxy.registerSignal(SIGUSR1, handle_signal);
    sproxy.registerSignal(SIGUSR2, handle_signal);

    return sproxy.run();
}
