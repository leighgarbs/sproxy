project(sproxy)

# CMake 2.6 is the oldest version of CMake that still has documentation available online
cmake_minimum_required(VERSION 2.6)

include(tools-cmake/ProjectCommon.cmake)

#==============================================================================================
# LIBSPROXY
#==============================================================================================

# Everything except the main() function builds into here.  main() is in main.cpp which is built
# into an executable that links to this.
set(SRC
  SleepProxy.cpp
  SleepProxyImpl.cpp
  SleepProxyFactory.cpp)

if(MACOS OR LINUX)
  list(APPEND SRC
    PosixSleepProxyImpl.cpp)
endif(MACOS OR LINUX)

add_library(${PROJECT_NAME} ${SRC})

# We need only this include directory, cmake will take care of including dependency headers
target_include_directories(${PROJECT_NAME} PUBLIC .)

# Add the tools-cpp library and link to it
add_subdirectory(tools-cpp)
target_link_libraries(${PROJECT_NAME} tools-cpp)

#==============================================================================================
# SPROXY-MAIN
#==============================================================================================

set(PROJECT_MAIN ${PROJECT_NAME}-main)

# Add the target that builds the sproxy executable
add_executable(${PROJECT_MAIN} main.cpp)

# We want to generate an executable named "sproxy", which normally add_executable would do, but
# the add_library above for libsproxy already defined the sproxy target
set_target_properties(${PROJECT_MAIN} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
target_link_libraries(${PROJECT_MAIN} ${PROJECT_NAME})

# Add test subdirectories (these don't build unconditionally)
if(MACOS OR LINUX)
  add_subdirectory(PosixSleepProxyImpl_test EXCLUDE_FROM_ALL)
endif(MACOS OR LINUX)
