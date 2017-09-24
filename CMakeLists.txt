project(sproxy)
cmake_minimum_required(VERSION 3.5)

# Flags used for all builds
set(COMMON_FLAGS "-Wall")

# Flags used for all builds on specific platforms
set(COMMON_LINUX_FLAGS "-DLINUX ${COMMON_FLAGS}")
set(COMMON_WINDOWS_FLAGS "-DWINDOWS ${COMMON_FLAGS}")

# Generate the LINUX variable
if(UNIX AND NOT APPLE)
  set(LINUX 1)
else(UNIX AND NOT APPLE)
  set(LINUX 0)
endif(UNIX AND NOT APPLE)

if(LINUX)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COMMON_LINUX_FLAGS}")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${COMMON_LINUX_FLAGS}")
elseif(WIN32)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${COMMON_WINDOWS_FLAGS}")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${COMMON_WINDOWS_FLAGS}")
endif(LINUX)

add_executable(sproxy sproxy.cpp)

add_subdirectory(toolbox)
target_link_libraries(sproxy toolbox)

include_directories(toolbox toolbox/networking)
