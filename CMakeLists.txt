cmake_minimum_required(VERSION 3.7)
project(rtmap-tracer C)

find_package(DynamoRIO REQUIRED)

add_library(rtmap_tracer SHARED tracer.c)
target_include_directories(rtmap_tracer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

use_DynamoRIO_extension(rtmap_tracer drmgr)
use_DynamoRIO_extension(rtmap_tracer drutil)
use_DynamoRIO_extension(rtmap_tracer drreg)
use_DynamoRIO_extension(rtmap_tracer drwrap)
use_DynamoRIO_extension(rtmap_tracer drsyms)

configure_DynamoRIO_client(rtmap_tracer)

target_link_libraries(rtmap_tracer rt)

