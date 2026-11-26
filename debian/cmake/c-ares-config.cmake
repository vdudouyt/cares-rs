# CMake package configuration for cares-rs, installed under the stock c-ares
# package name so find_package(c-ares) and the c-ares::cares target work
# unchanged. Paths are derived relative to this file's install location:
# <prefix>/lib/<triplet>/cmake/c-ares/.
get_filename_component(_c_ares_libdir "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
get_filename_component(_c_ares_prefix "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

if(NOT TARGET c-ares::cares)
  add_library(c-ares::cares SHARED IMPORTED)
  set_target_properties(c-ares::cares PROPERTIES
    IMPORTED_LOCATION "${_c_ares_libdir}/libcares.so.2"
    INTERFACE_INCLUDE_DIRECTORIES "${_c_ares_prefix}/include")
endif()

if(NOT TARGET c-ares::cares_shared)
  add_library(c-ares::cares_shared INTERFACE IMPORTED)
  set_target_properties(c-ares::cares_shared PROPERTIES
    INTERFACE_LINK_LIBRARIES "c-ares::cares")
endif()

set(c-ares_LIBRARY c-ares::cares)
set(c-ares_SHARED_LIBRARY c-ares::cares_shared)
set(CARES_FOUND 1)
set(CARES_LIBRARIES c-ares::cares)
