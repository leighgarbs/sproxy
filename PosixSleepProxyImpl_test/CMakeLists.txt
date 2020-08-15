# Include common project setup
include(${PROJECT_SOURCE_DIR}/tools-cmake/ProjectCommon.cmake)

# All the source files for this test
set(SRC PosixSleepProxyImpl_test.cpp)

# We need these include directories
set(INC . ..)

# Link against the project library
set(LIB ${PROJECT_NAME})

# This test can fail if its run in an environment where RawSocket isn't
# functional.  In these cases the test outputs 2 and is skipped.
add_test_executable(PosixSleepProxyImpl_test "${SRC}" "${INC}" "${LIB}")
