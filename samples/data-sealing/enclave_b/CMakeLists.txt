# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

set(BASH bash.exe)
set(OE_BIN_DIR ..\\..\\..\\..\\..\\bin)

include(maybe_build_using_clangw)

add_executable(enclave_b ecalls.cpp)
maybe_build_using_clangw(enclave_b)
target_link_libraries(enclave_b common)
