# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(PROJECT_NAME TpmCpp)
project(${PROJECT_NAME} CXX)

# Release by default
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
    message(STATUS "Build type not specified: Use Release by default.")
endif(NOT CMAKE_BUILD_TYPE)

# Set output directory and enable debug symbols for release
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/debug")
else()
  set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/release")
  if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
  endif(NOT MSVC)
endif()

file(GLOB SRC_FILES
    *.cpp
)

add_definitions(-D_TPMCPPLIB)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -Wno-cast-function-type")  

add_library(${PROJECT_NAME} STATIC ${SRC_FILES})

include_directories(../)

target_link_libraries(${PROJECT_NAME}
    -L/usr/lib
    -lssl
    -lcrypto
)
