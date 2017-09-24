project(sproxy)
cmake_minimum_required(VERSION 3.5)

# This project depends on the project in the toolbox subdirectory
add_subdirectory(toolbox)

# Include common project setup
include(${CMAKE_CURRENT_LIST_DIR}/cmake/ProjectCommon.cmake)

# This project outputs this executable
add_executable(${PROJECT_NAME} sproxy.cpp)

# We need to link toolbox
target_link_libraries(${PROJECT_NAME} toolbox)

# Include toolbox headers
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE
  toolbox toolbox/networking)
