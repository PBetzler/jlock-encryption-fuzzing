cmake_minimum_required(VERSION 3.16)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
project(cpp-demo)

# Export compilation database
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

find_package(cifuzz NO_SYSTEM_ENVIRONMENT_PATH)
enable_testing()
include(GoogleTest)
enable_fuzz_testing()

add_library(crypto
    ${CMAKE_SOURCE_DIR}/src/libchecksum.c
    ${CMAKE_SOURCE_DIR}/src/libchecksum.h
    ${CMAKE_SOURCE_DIR}/src/libcrypt.c
    ${CMAKE_SOURCE_DIR}/src/libcrypt.h
    ${CMAKE_SOURCE_DIR}/src/libutils.c
    ${CMAKE_SOURCE_DIR}/src/libutils.h
)

target_include_directories(crypto PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(crypto
    OpenSSL::Crypto
)

add_executable(main_executable
    ${CMAKE_SOURCE_DIR}/src/main.c
)

target_link_libraries(main_executable
    crypto
)

add_subdirectory(fuzz-tests)
