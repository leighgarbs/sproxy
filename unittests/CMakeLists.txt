add_custom_target(${PROJECT_NAME}-unittests)

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/../common/ProjectCommon.cmake)

set(INCLUDE_DIRS ${CMAKE_CURRENT_LIST_DIR}/..)

set(LINK_LIBRARIES ${PROJECT_NAME})

add_unittest(SleepProxy.ut "${INCLUDE_DIRS}" "${LINK_LIBRARIES}")
