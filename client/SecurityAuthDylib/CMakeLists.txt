cmake_minimum_required(VERSION 3.15)
project(SecurityAuthDylib LANGUAGES C OBJC)

set(CMAKE_C_STANDARD 11)
set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0")
set(CMAKE_OSX_ARCHITECTURES "arm64")

include_directories(include)

file(GLOB_RECURSE SOURCES
    src/*.m
    src/*.c
)

add_library(SecurityAuth SHARED ${SOURCES})

set_target_properties(SecurityAuth PROPERTIES
    OUTPUT_NAME "SecurityAuth"
    PREFIX ""
    SUFFIX ".dylib"
    INSTALL_NAME_DIR "@rpath/Frameworks"
    C_VISIBILITY_PRESET hidden
)

target_link_libraries(SecurityAuth
    "-framework Foundation"
    "-framework UIKit"
    "-framework Security"
)
