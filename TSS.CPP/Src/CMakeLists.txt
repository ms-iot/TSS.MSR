# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

set(PROJECT_NAME TpmCpp)
project(${PROJECT_NAME} CXX)

file(GLOB SRC_FILES
    *.cpp
)

add_definitions(-D_TPMCPPLIB)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(${PROJECT_NAME} STATIC ${SRC_FILES})

include_directories(../)

target_link_libraries(${PROJECT_NAME}
    -L/usr/lib
    -lssl
    -lcrypto
)
