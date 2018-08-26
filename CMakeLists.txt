project(sproxy)

# CMake 2.6 is the oldest version of CMake that still has documentation
# available online
cmake_minimum_required(VERSION 2.6)

# This project depends on the project in the toolbox subdirectory
add_subdirectory(toolbox)
add_subdirectory(unittests)

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/common/ProjectCommon.cmake)

# This project outputs this executable
add_executable(${PROJECT_NAME} main.cpp SleepProxy.cpp)

# We need to link toolbox
target_link_libraries(${PROJECT_NAME} toolbox)

# Include toolbox headers
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE
  . toolbox toolbox/networking)
