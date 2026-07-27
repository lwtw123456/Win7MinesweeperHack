cmake_minimum_required(VERSION 3.20)
project(MinePicker LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "MinePicker is a Windows-only project.")
endif()

add_library(MinePicker SHARED
    MinePicker.cpp
    MinePicker.h
)

target_compile_features(MinePicker PRIVATE cxx_std_17)
target_compile_definitions(MinePicker PRIVATE
    MINEPICKER_BUILD
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_link_libraries(MinePicker PRIVATE user32 gdi32)
set_target_properties(MinePicker PROPERTIES PREFIX "")

if(MSVC)
    target_compile_options(MinePicker PRIVATE /utf-8 /W4 /EHsc /permissive-)
endif()
