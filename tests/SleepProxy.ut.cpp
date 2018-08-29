#include <stdexcept>

#include "SleepProxy.hpp"

int main(int argc, char** argv)
{
    int return_code = 0;

    try
    {
        SleepProxy sleep_proxy(argc, argv, 0.1);
    }
    catch (std::runtime_error ex)
    {
        // Return the "skipped" code
        return_code = 2;
    }

    return return_code;
}
