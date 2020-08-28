cmake_minimum_required(VERSION 3.16)
project(mpatch C)

set(CMAKE_C_STANDARD 99)

add_library(mpatch mpatch.c mpatch.h)
