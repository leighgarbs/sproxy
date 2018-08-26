project(sproxy)

# CMake 2.6 is the oldest version of CMake that still has documentation
# available online
cmake_minimum_required(VERSION 2.6)

# This project depends on the project in the toolbox subdirectory
add_subdirectory(toolbox)
add_subdirectory(tests EXCLUDE_FROM_ALL)

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/common/ProjectCommon.cmake)

# Base code is built into a library because it's easier this way ... main.cpp
# links to it
add_library(${PROJECT_NAME} SleepProxy.cpp)
target_link_libraries(${PROJECT_NAME} toolbox)
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE
  . toolbox toolbox/networking)

# Add the target that builds the sproxy executable
add_executable(${PROJECT_NAME}-main main.cpp)
set_target_properties(${PROJECT_NAME}-main
  PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
target_link_libraries(${PROJECT_NAME}-main ${PROJECT_NAME})
