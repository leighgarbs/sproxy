project(sproxy)
cmake_minimum_required(VERSION 3.5)

# This project depends on the project in the toolbox subdirectory
add_subdirectory(toolbox)

# Flags used for all builds
set(${PROJECT_NAME}_COMMON_FLAGS "-Wall")

# Flags used for all builds on specific platforms
set(${PROJECT_NAME}_COMMON_LINUX_FLAGS
  "-DLINUX ${${PROJECT_NAME}_COMMON_FLAGS}")
set(${PROJECT_NAME}_COMMON_WINDOWS_FLAGS
  "-DWINDOWS ${${PROJECT_NAME}_COMMON_FLAGS}")

# Generate the LINUX variable
if(UNIX AND NOT APPLE)
  set(LINUX 1)
else(UNIX AND NOT APPLE)
  set(LINUX 0)
endif(UNIX AND NOT APPLE)

if(LINUX)
  set(CMAKE_CXX_FLAGS_DEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} ${${PROJECT_NAME}_COMMON_LINUX_FLAGS}")
  set(CMAKE_CXX_FLAGS_RELEASE
    "${CMAKE_CXX_FLAGS_RELEASE} ${${PROJECT_NAME}_COMMON_LINUX_FLAGS}")
elseif(WIN32)
  set(CMAKE_CXX_FLAGS_DEBUG
    "${CMAKE_CXX_FLAGS_DEBUG} ${${PROJECT_NAME}_COMMON_WINDOWS_FLAGS}")
  set(CMAKE_CXX_FLAGS_RELEASE
    "${CMAKE_CXX_FLAGS_RELEASE} ${${PROJECT_NAME}_COMMON_WINDOWS_FLAGS}")
endif(LINUX)

# This project outputs this executable
add_executable(${PROJECT_NAME} sproxy.cpp)

# We need to link toolbox
target_link_libraries(${PROJECT_NAME} toolbox)

# Include toolbox headers
target_include_directories(${PROJECT_NAME} SYSTEM PRIVATE
  toolbox toolbox/networking)
