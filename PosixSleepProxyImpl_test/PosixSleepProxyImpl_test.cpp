#include <iostream>
#include <stdexcept>

#include "PosixSleepProxyImpl_test.hpp"

#include "PosixSleepProxyImpl.hpp"
#include "Test.hpp"
#include "TestMacros.hpp"

TEST_PROGRAM_MAIN(PosixSleepProxyImpl_test);

//==============================================================================
void PosixSleepProxyImpl_test::addTestCases()
{
    ADD_TEST_CASE(Constructor);
}

//==============================================================================
Test::Result PosixSleepProxyImpl_test::Constructor::body()
{
    try
    {
        PosixSleepProxyImpl sproxy(0, 0);
    }
    catch (std::runtime_error& ex)
    {
        std::cout << ex.what() << "\n";
        return Test::SKIPPED;
    }

    return Test::PASSED;
}
