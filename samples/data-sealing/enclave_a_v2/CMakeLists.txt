# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(BASH bash.exe)
set(OE_BIN_DIR ..\\..\\..\\..\\..\\bin)

#maybe_build_using_clangw enables the building of ELF enclaves using CLang on Windows
include(maybe_build_using_clangw)

add_executable(enclave_a_v2 ecalls.cpp)
maybe_build_using_clangw(enclave_a_v2)
target_link_libraries(enclave_a_v2 common)
