#include "SleepProxy.hpp"

int main(int argc, char** argv)
{
    SleepProxy sproxy(argc, argv, 1);

    sproxy.run();

    return 1;
}
