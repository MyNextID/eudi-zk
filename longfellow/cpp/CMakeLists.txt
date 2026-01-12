# longfellow/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(longfellow_wrapper VERSION 0.1.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(APPLE)
    link_directories(/opt/homebrew/lib)
    include_directories(/opt/homebrew/include)
endif()

# Find OpenSSL (required by Longfellow)
find_package(OpenSSL REQUIRED)
find_package(zstd REQUIRED)

# Find zstd (required by Longfellow)
find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED libzstd)

# Longfellow-ZK library path
set(LONGFELLOW_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../vendor/longfellow-zk")
set(LONGFELLOW_BUILD_DIR "${LONGFELLOW_DIR}/clang-build-release")

# Check if Longfellow is built
if(NOT EXISTS "${LONGFELLOW_BUILD_DIR}")
    message(STATUS "Longfellow not built yet. Building...")
    execute_process(
        COMMAND bash -c "cd ${LONGFELLOW_DIR} && CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B clang-build-release && cd clang-build-release && make -j4"
        RESULT_VARIABLE BUILD_RESULT
    )
    if(NOT BUILD_RESULT EQUAL 0)
        message(FATAL_ERROR "Failed to build Longfellow-ZK")
    endif()
endif()

# Find the actual Longfellow library file
file(GLOB_RECURSE LONGFELLOW_LIB "${LONGFELLOW_BUILD_DIR}/*.a")
if(NOT LONGFELLOW_LIB)
    message(FATAL_ERROR "Could not find Longfellow library in ${LONGFELLOW_BUILD_DIR}")
endif()
list(GET LONGFELLOW_LIB 0 LONGFELLOW_LIB)  # Take first .a file if multiple found
message(STATUS "Found Longfellow library: ${LONGFELLOW_LIB}")

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LONGFELLOW_DIR}/lib
    ${OPENSSL_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIRS}
)

# ============== Shared Library (for CGo) ==============
# Source files for the wrapper library
set(WRAPPER_SOURCES
    src/ecdsa-circuit.cpp
    src/ecdsa_c.cpp
)

# Create shared library (for CGo)
add_library(longfellow_wrapper SHARED ${WRAPPER_SOURCES})

# Link libraries
target_link_libraries(longfellow_wrapper
    ${LONGFELLOW_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ZSTD_LIBRARIES}
)

# Set library output name
set_target_properties(longfellow_wrapper PROPERTIES
    OUTPUT_NAME "longfellow_wrapper"
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

# Install rules
install(TARGETS longfellow_wrapper
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(FILES include/ecdsa_c.h
    DESTINATION include
)

# ============== Testing ==============
# Enable testing
enable_testing()

# Find Google Test
find_package(GTest REQUIRED)

# Test executable
add_executable(ecdsa_tests
    src/ecdsa-circuit.cpp
    src/ecdsa-circuit_test.cpp
    src/compare-bytes.cpp
    src/compare-bytes_test.cpp
)

add_executable(compare_bytes_tests
    src/compare-bytes.cpp
    src/compare-bytes_test.cpp
)

# Include directories for tests
target_include_directories(ecdsa_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LONGFELLOW_DIR}/lib
    ${OPENSSL_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIRS}
    ${GTEST_INCLUDE_DIRS}
)

# Include directories for tests
target_include_directories(compare_bytes_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${LONGFELLOW_DIR}/lib
    ${OPENSSL_INCLUDE_DIR}
    ${ZSTD_INCLUDE_DIRS}
    ${GTEST_INCLUDE_DIRS}
)

# Link libraries for tests
target_link_libraries(ecdsa_tests
    ${LONGFELLOW_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ZSTD_LIBRARIES}
    GTest::GTest
    GTest::Main
    pthread
)

# Link libraries for tests
target_link_libraries(compare_bytes_tests
    ${LONGFELLOW_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${ZSTD_LIBRARIES}
    GTest::GTest
    GTest::Main
    pthread
)

# Register test with CTest
add_test(NAME ecdsa_tests COMMAND ecdsa_tests)

# Register test with CTest
add_test(NAME compare_bytes_tests COMMAND compare_bytes_tests)