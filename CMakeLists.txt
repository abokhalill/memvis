cmake_minimum_required(VERSION 3.7)
project(memvis-tracer C)

find_package(DynamoRIO REQUIRED)

add_library(memvis_tracer SHARED tracer.c)
target_include_directories(memvis_tracer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

use_DynamoRIO_extension(memvis_tracer drmgr)
use_DynamoRIO_extension(memvis_tracer drutil)
use_DynamoRIO_extension(memvis_tracer drreg)

configure_DynamoRIO_client(memvis_tracer)

target_link_libraries(memvis_tracer rt)

