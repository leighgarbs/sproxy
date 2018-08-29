add_custom_target(${PROJECT_NAME}-tests)

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/../common/ProjectCommon.cmake)

set(INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/..)

set(LINK_LIBRARIES ${PROJECT_NAME})

# This test can fail if its run in an environment where RawSocket isn't
# functional.  In these cases the test outputs 2 and is skipped.
add_test_executable(SleepProxy.ut "${INCLUDE_DIRS}" "${LINK_LIBRARIES}")
set_property(TEST SleepProxy.ut PROPERTY SKIP_RETURN_CODE 2)
