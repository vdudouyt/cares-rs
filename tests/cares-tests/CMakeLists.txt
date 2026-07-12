cmake_minimum_required(VERSION 3.10)
project(AresTest)

set(CMAKE_CXX_STANDARD 11)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Use c-ares 1.34.6 headers instead of system 1.27.0
include_directories(BEFORE src/include/cares)
add_compile_definitions(CARES_STATICLIB CARES_THREADS)

add_executable(arestest src/main.cc src/loader.cc src/dns-proto.cc src/ares-test.cc src/ares-test-parse-a.cc src/ares-test-parse-aaaa.cc src/ares-test-parse-caa.cc src/ares-test-parse-mx.cc src/ares-test-parse-naptr.cc src/ares-test-parse-ns.cc src/ares-test-parse-ptr.cc src/ares-test-parse-soa-any.cc src/ares-test-parse-soa.cc src/ares-test-parse-srv.cc src/ares-test-parse-txt.cc src/ares-test-parse-uri.cc src/ares-test-live.cc src/ares-test-mock-ai.cc src/ares-test-mock.cc src/ares-test-misc.cc src/ares-test-init.cc src/ares-test-parse.cc src/dns-proto-test.cc)
target_link_libraries(arestest GTest::GTest GTest::Main GTest::gmock pthread)

# Fuzz corpus test binaries (modern mode — exercises ares_dns_parse/write round-trip)
add_executable(aresfuzz src/ares-fuzz-main.cc src/ares-test-fuzz.c src/loader.cc)
target_link_libraries(aresfuzz pthread)

add_executable(aresfuzzname src/ares-fuzz-main.cc src/ares-test-fuzz-name.c src/loader.cc)
target_link_libraries(aresfuzzname pthread)
