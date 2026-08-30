cmake_minimum_required(VERSION 3.22)

project(utreexo_bridge VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

option(UTREEXO_BUILD_RPC "Build the Bitcoin Core JSON-RPC adapter" ON)
option(UTREEXO_BUILD_BENCHMARKS "Build deterministic resource estimation tools" ON)
option(UTREEXO_ENABLE_REGTEST_INTEGRATION "Enable external Core/bridge/Floresta differential test" OFF)
set(UTREEXO_REFERENCE_BRIDGE_EXECUTABLE "" CACHE FILEPATH "Path to rpc-utreexo-bridge")
set(FLORESTAD_EXECUTABLE "" CACHE FILEPATH "Path to florestad")
set(UTREEXO_UNIVALUE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/univalue" CACHE PATH
    "Path to the vendored UniValue source tree")

add_library(utreexo_logging src/log.cpp)
target_include_directories(utreexo_logging PUBLIC include)
target_compile_features(utreexo_logging PUBLIC cxx_std_20)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(utreexo_logging PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

add_library(utreexo_accumulator
    src/bridge_wire.cpp
    src/hash.cpp
    src/leaf.cpp
    src/position.cpp
    src/forest.cpp
)
target_include_directories(utreexo_accumulator PUBLIC include)
target_compile_features(utreexo_accumulator PUBLIC cxx_std_20)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(utreexo_accumulator PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

add_library(utreexo_checkpoint src/checkpoint.cpp)
target_include_directories(utreexo_checkpoint PUBLIC include)
target_compile_features(utreexo_checkpoint PUBLIC cxx_std_20)
target_link_libraries(utreexo_checkpoint PUBLIC utreexo_accumulator utreexo_logging)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(utreexo_checkpoint PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
endif()

if(UTREEXO_BUILD_BENCHMARKS)
    add_executable(utreexo-resource-estimate bench/resource_estimate.cpp)
    target_compile_features(utreexo-resource-estimate PRIVATE cxx_std_20)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(utreexo-resource-estimate PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
    endif()
endif()

if(UTREEXO_BUILD_RPC)
    if(NOT EXISTS "${UTREEXO_UNIVALUE_DIR}/include/univalue.h")
        message(FATAL_ERROR "Vendored UniValue was not found; set UTREEXO_UNIVALUE_DIR or disable UTREEXO_BUILD_RPC")
    endif()

    add_library(utreexo_univalue STATIC
        ${UTREEXO_UNIVALUE_DIR}/lib/univalue.cpp
        ${UTREEXO_UNIVALUE_DIR}/lib/univalue_get.cpp
        ${UTREEXO_UNIVALUE_DIR}/lib/univalue_read.cpp
        ${UTREEXO_UNIVALUE_DIR}/lib/univalue_write.cpp
    )
    target_include_directories(utreexo_univalue SYSTEM PUBLIC
        ${UTREEXO_UNIVALUE_DIR}/include)
    target_compile_features(utreexo_univalue PUBLIC cxx_std_20)

    add_library(utreexo_core_rpc
        src/core_rpc.cpp
        src/sync.cpp
    )
    target_include_directories(utreexo_core_rpc PUBLIC include)
    target_compile_features(utreexo_core_rpc PUBLIC cxx_std_20)
    target_link_libraries(utreexo_core_rpc PUBLIC utreexo_accumulator utreexo_univalue utreexo_logging)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(utreexo_core_rpc PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
    endif()

    add_executable(utreexo-bridge src/main.cpp)
    target_link_libraries(utreexo-bridge PRIVATE utreexo_core_rpc utreexo_checkpoint)
    target_compile_definitions(utreexo-bridge PRIVATE
        UTREEXO_BRIDGE_VERSION="${PROJECT_VERSION}")
endif()

if(BUILD_TESTING)
    add_executable(utreexo_tests
        test/test_main.cpp
        test/hash_tests.cpp
        test/leaf_tests.cpp
        test/position_tests.cpp
        test/forest_tests.cpp
        test/rustreexo_vector_tests.cpp
        test/checkpoint_tests.cpp
        test/bridge_wire_tests.cpp
        test/log_tests.cpp
    )
    target_link_libraries(utreexo_tests PRIVATE utreexo_accumulator utreexo_checkpoint utreexo_logging)
    target_include_directories(utreexo_tests PRIVATE test)
    target_compile_features(utreexo_tests PRIVATE cxx_std_20)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(utreexo_tests PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
    endif()
    add_test(NAME utreexo_tests COMMAND utreexo_tests)

    if(UTREEXO_BUILD_RPC)
        add_executable(utreexo_rpc_tests
            test/test_main.cpp
            test/core_rpc_tests.cpp
            test/sync_tests.cpp
        )
        target_link_libraries(utreexo_rpc_tests PRIVATE utreexo_core_rpc)
        target_include_directories(utreexo_rpc_tests PRIVATE test)
        target_compile_features(utreexo_rpc_tests PRIVATE cxx_std_20)
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(utreexo_rpc_tests PRIVATE
                -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror)
        endif()
        add_test(NAME utreexo_rpc_tests COMMAND utreexo_rpc_tests)

        if(UTREEXO_ENABLE_REGTEST_INTEGRATION)
            find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
            add_test(NAME utreexo_floresta_regtest
                COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_CURRENT_SOURCE_DIR}/test/integration/floresta_regtest.py
                    --sidecar=$<TARGET_FILE:utreexo-bridge>
                    --reference-bridge=${UTREEXO_REFERENCE_BRIDGE_EXECUTABLE}
                    --florestad=${FLORESTAD_EXECUTABLE})
            set_tests_properties(utreexo_floresta_regtest PROPERTIES
                SKIP_RETURN_CODE 77 TIMEOUT 600)
        endif()
    endif()
endif()
