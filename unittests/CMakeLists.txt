add_custom_target(unittests-${PROJECT_NAME})

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/../common/ProjectCommon.cmake)

set(INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/..)

set(LINK_LIBRARIES toolbox)

add_unittest(SleepProxy.ut "${INCLUDE_DIRS}" "${LINK_LIBRARIES}")
