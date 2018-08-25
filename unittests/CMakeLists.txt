add_custom_target(unittests)
add_dependencies(unittests sproxy)

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/../common/ProjectCommon.cmake)

add_unittest(SleepProxy.ut)
