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
    sproxy.attachSignal(SIGINT,  handle_signal);
    sproxy.attachSignal(SIGTERM, handle_signal);
    sproxy.attachSignal(SIGUSR1, handle_signal);
    sproxy.attachSignal(SIGUSR2, handle_signal);

    return sproxy.run();
}
