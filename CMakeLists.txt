cmake_minimum_required(VERSION 3.10)

project(vita-core-dump LANGUAGES C)

set(CMAKE_C_STANDARD 11)

include(FindPkgConfig)
pkg_search_module(ZLib REQUIRED IMPORTED_TARGET zlib)
pkg_search_module(LibElf REQUIRED IMPORTED_TARGET libelf)
pkg_search_module(LibDw REQUIRED IMPORTED_TARGET libdw)

include(TestBigEndian)
test_big_endian(is_big_endian)

if (is_big_endian)
	message(FATAL_ERROR "vita-core-dump does not work on big endian systems")
endif()

add_compile_options(-Wall -Wextra)

add_executable(
	vita-core-dump
	main.c
	vc_address_space.h
	vc_address_space.c
	vc_core.h
	vc_core.c
	vc_elf.h
	vc_elf.c
)

# libstdc++ is required for demangling
target_link_libraries(vita-core-dump PRIVATE "stdc++")

target_link_libraries(vita-core-dump PRIVATE PkgConfig::ZLib)
target_link_libraries(vita-core-dump PRIVATE PkgConfig::LibElf)
target_link_libraries(vita-core-dump PRIVATE PkgConfig::LibDw)
