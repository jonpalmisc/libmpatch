cmake_minimum_required(VERSION 3.16)
project(mpatch VERSION 2.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)

add_library(mpatch mpatch.c mpatch.h)

add_library(example SHARED example/example.m mpatch.c)
target_link_libraries(example "-framework CoreFoundation")
