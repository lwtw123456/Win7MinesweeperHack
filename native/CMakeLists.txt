cmake_minimum_required(VERSION 3.20)
project(MinesweeperWndProcHook LANGUAGES CXX)

add_library(
    MinesweeperWndProcHook
    SHARED
    MinesweeperWndProcHook.cpp
)

target_compile_features(
    MinesweeperWndProcHook
    PRIVATE
    cxx_std_20
)

target_compile_definitions(
    MinesweeperWndProcHook
    PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(
    MinesweeperWndProcHook
    PRIVATE
    user32
)

set_target_properties(
    MinesweeperWndProcHook
    PROPERTIES
    OUTPUT_NAME "MinesweeperWndProcHook"
)

if(MSVC)
    set_property(
        TARGET MinesweeperWndProcHook
        PROPERTY
        MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>"
    )

    target_compile_options(
        MinesweeperWndProcHook
        PRIVATE
        /W4
        /permissive-
        /EHsc
    )
endif()
