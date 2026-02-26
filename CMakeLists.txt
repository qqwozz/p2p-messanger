cmake_minimum_required(VERSION 3.16)

project(p2p_messenger LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)

add_library(crypto STATIC
    src/crypto/crypto.cpp
)

target_include_directories(crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(crypto
    PUBLIC
        OpenSSL::Crypto
)

add_library(network STATIC
    src/network/network.cpp
)

target_include_directories(network
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(network
    PUBLIC
        Boost::system
)

add_executable(crypto_tests
    tests/crypto_tests.cpp
)

target_link_libraries(crypto_tests
    PRIVATE
        crypto
        OpenSSL::Crypto
)

add_executable(network_tests
    tests/network_tests.cpp
)

target_link_libraries(network_tests
    PRIVATE
        network
        Boost::system
)

enable_testing()
add_test(NAME crypto_tests COMMAND crypto_tests)
add_test(NAME network_tests COMMAND network_tests)

