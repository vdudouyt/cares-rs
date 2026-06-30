# CMake package configuration for cares-rs (own-name; not a c-ares drop-in).
# Provides the imported target cares-rs::cares_rs. Paths are derived relative to
# this file's install location: <prefix>/lib/<triplet>/cmake/cares-rs/.
get_filename_component(_cares_rs_libdir "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
get_filename_component(_cares_rs_prefix "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

if(NOT TARGET cares-rs::cares_rs)
  add_library(cares-rs::cares_rs SHARED IMPORTED)
  set_target_properties(cares-rs::cares_rs PROPERTIES
    IMPORTED_LOCATION "${_cares_rs_libdir}/libcares_rs.so.2"
    INTERFACE_INCLUDE_DIRECTORIES "${_cares_rs_prefix}/include/cares-rs")
endif()
