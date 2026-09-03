cmake_minimum_required(VERSION 3.22)

project(utreexo_bridge VERSION 0.4.0 LANGUAGES CXX)

include(CTest)
include(GNUInstallDirs)
find_package(Threads REQUIRED)

configure_file(
    contrib/systemd/utreexo-bridge.service.in
    ${CMAKE_CURRENT_BINARY_DIR}/utreexo-bridge.service
    @ONLY)

option(UTREEXO_BUILD_RPC "Build the Bitcoin Core JSON-RPC adapter" ON)
option(UTREEXO_BUILD_BENCHMARKS "Build deterministic resource estimation tools" ON)
option(UTREEXO_BUILD_FUZZERS "Build libFuzzer targets (requires Clang)" OFF)
option(UTREEXO_ENABLE_REGTEST_INTEGRATION "Enable external Core/bridge/Floresta differential test" OFF)
option(UTREEXO_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
set(UTREEXO_SANITIZERS "" CACHE STRING
    "Comma-separated compiler sanitizers (for example: address,undefined or thread)")
if(UTREEXO_BUILD_FUZZERS AND NOT UTREEXO_SANITIZERS)
    set(UTREEXO_SANITIZERS "address,undefined")
endif()

set(UTREEXO_REFERENCE_BRIDGE_EXECUTABLE "" CACHE FILEPATH "Path to rpc-utreexo-bridge")
set(FLORESTAD_EXECUTABLE "" CACHE FILEPATH "Path to florestad")
set(UTREEXO_UNIVALUE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/univalue" CACHE PATH
    "Path to the vendored UniValue source tree")

add_library(utreexo_warnings INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(utreexo_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow
        -Wformat=2
        -Wundef)
    if(UTREEXO_WARNINGS_AS_ERRORS)
        target_compile_options(utreexo_warnings INTERFACE -Werror)
    endif()
endif()

add_library(utreexo_sanitizers INTERFACE)
if(UTREEXO_SANITIZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "UTREEXO_SANITIZERS requires GCC or Clang")
    endif()
    if(UTREEXO_SANITIZERS MATCHES "(^|,)address(,|$)" AND
       UTREEXO_SANITIZERS MATCHES "(^|,)thread(,|$)")
        message(FATAL_ERROR "AddressSanitizer and ThreadSanitizer cannot be enabled together")
    endif()
    if(NOT UTREEXO_SANITIZERS MATCHES
       "^(address|undefined|thread|leak)(,(address|undefined|thread|leak))*$")
        message(FATAL_ERROR "Unsupported value in UTREEXO_SANITIZERS=${UTREEXO_SANITIZERS}")
    endif()
    target_compile_options(utreexo_sanitizers INTERFACE
        -fno-omit-frame-pointer
        "-fsanitize=${UTREEXO_SANITIZERS}")
    target_link_options(utreexo_sanitizers INTERFACE
        "-fsanitize=${UTREEXO_SANITIZERS}")
endif()

function(utreexo_configure_target target)
    target_link_libraries(${target} PRIVATE utreexo_warnings utreexo_sanitizers)
endfunction()

add_library(utreexo_logging src/log.cpp src/memory.cpp)
target_include_directories(utreexo_logging PUBLIC include)
target_compile_features(utreexo_logging PUBLIC cxx_std_20)
utreexo_configure_target(utreexo_logging)

add_library(utreexo_accumulator
    src/bridge_wire.cpp
    src/hash.cpp
    src/leaf.cpp
    src/position.cpp
    src/forest.cpp
)
target_include_directories(utreexo_accumulator PUBLIC include)
target_compile_features(utreexo_accumulator PUBLIC cxx_std_20)
utreexo_configure_target(utreexo_accumulator)

add_library(utreexo_p2p src/p2p.cpp src/proof_store.cpp)
target_include_directories(utreexo_p2p PUBLIC include)
target_compile_features(utreexo_p2p PUBLIC cxx_std_20)
target_link_libraries(utreexo_p2p PUBLIC utreexo_accumulator utreexo_logging Threads::Threads)
utreexo_configure_target(utreexo_p2p)

add_library(utreexo_checkpoint src/checkpoint.cpp src/trusted_checkpoint.cpp)
target_include_directories(utreexo_checkpoint PUBLIC include)
target_compile_features(utreexo_checkpoint PUBLIC cxx_std_20)
target_link_libraries(utreexo_checkpoint PUBLIC utreexo_accumulator utreexo_logging)
utreexo_configure_target(utreexo_checkpoint)

add_executable(utreexo-checkpoint-compact src/checkpoint_compact.cpp)
target_link_libraries(utreexo-checkpoint-compact PRIVATE utreexo_logging)
target_compile_features(utreexo-checkpoint-compact PRIVATE cxx_std_20)
utreexo_configure_target(utreexo-checkpoint-compact)

if(UTREEXO_BUILD_BENCHMARKS)
    add_executable(utreexo-resource-estimate bench/resource_estimate.cpp)
    target_compile_features(utreexo-resource-estimate PRIVATE cxx_std_20)
    utreexo_configure_target(utreexo-resource-estimate)
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
    target_link_libraries(utreexo_univalue PRIVATE utreexo_sanitizers)

    add_library(utreexo_core_rpc
        src/core_rpc.cpp
        src/json_stream.cpp
        src/sync.cpp
    )
    target_include_directories(utreexo_core_rpc PUBLIC include)
    target_compile_features(utreexo_core_rpc PUBLIC cxx_std_20)
    target_link_libraries(utreexo_core_rpc PUBLIC utreexo_accumulator utreexo_univalue utreexo_logging Threads::Threads)
    utreexo_configure_target(utreexo_core_rpc)

    add_executable(utreexo-bridge src/main.cpp)
    target_link_libraries(utreexo-bridge PRIVATE utreexo_core_rpc utreexo_checkpoint utreexo_p2p)
    target_compile_definitions(utreexo-bridge PRIVATE
        UTREEXO_BRIDGE_VERSION="${PROJECT_VERSION}")
    utreexo_configure_target(utreexo-bridge)
endif()

if(UTREEXO_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "UTREEXO_BUILD_FUZZERS requires Clang with libFuzzer")
    endif()
    if(NOT UTREEXO_BUILD_RPC)
        message(FATAL_ERROR "UTREEXO_BUILD_FUZZERS requires UTREEXO_BUILD_RPC=ON")
    endif()

    add_executable(utreexo_fuzz_forest test/fuzz/forest.cpp)
    target_link_libraries(utreexo_fuzz_forest PRIVATE utreexo_accumulator)

    add_executable(utreexo_fuzz_rpc_json test/fuzz/rpc_json.cpp)
    target_link_libraries(utreexo_fuzz_rpc_json PRIVATE utreexo_core_rpc)

    add_executable(utreexo_fuzz_p2p test/fuzz/p2p.cpp)
    target_link_libraries(utreexo_fuzz_p2p PRIVATE utreexo_p2p)

    foreach(fuzz_target IN ITEMS utreexo_fuzz_forest utreexo_fuzz_rpc_json utreexo_fuzz_p2p)
        target_compile_features(${fuzz_target} PRIVATE cxx_std_20)
        target_compile_options(${fuzz_target} PRIVATE
            -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)
        target_link_options(${fuzz_target} PRIVATE
            -fsanitize=fuzzer,address,undefined)
        utreexo_configure_target(${fuzz_target})
    endforeach()
endif()

if(BUILD_TESTING)
    add_executable(utreexo_tests
        test/test_main.cpp
        test/hash_tests.cpp
        test/leaf_tests.cpp
        test/position_tests.cpp
        test/forest_tests.cpp
        test/online_forest_tests.cpp
        test/rustreexo_vector_tests.cpp
        test/checkpoint_tests.cpp
        test/trusted_checkpoint_tests.cpp
        test/bridge_wire_tests.cpp
        test/p2p_tests.cpp
        test/proof_store_tests.cpp
        test/log_tests.cpp
        test/memory_tests.cpp
    )
    target_link_libraries(utreexo_tests PRIVATE utreexo_accumulator utreexo_checkpoint utreexo_logging utreexo_p2p)
    target_include_directories(utreexo_tests PRIVATE test)
    target_compile_features(utreexo_tests PRIVATE cxx_std_20)
    utreexo_configure_target(utreexo_tests)
    add_test(NAME utreexo_tests COMMAND utreexo_tests)

    add_test(NAME mainnet_rebuild_validate_tests
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test/mainnet_rebuild_validate_tests.sh)
    set_tests_properties(mainnet_rebuild_validate_tests PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 60)

    add_test(NAME checkpoint_compact_safety_tests
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test/checkpoint_compact_safety_tests.sh
            $<TARGET_FILE:utreexo-checkpoint-compact>)
    set_tests_properties(checkpoint_compact_safety_tests PROPERTIES
        SKIP_RETURN_CODE 77 TIMEOUT 120)

    if(UTREEXO_BUILD_RPC)
        add_executable(utreexo_rpc_tests
            test/test_main.cpp
            test/core_rpc_tests.cpp
            test/sync_tests.cpp
        )
        target_link_libraries(utreexo_rpc_tests PRIVATE utreexo_core_rpc utreexo_p2p)
        target_include_directories(utreexo_rpc_tests PRIVATE test)
        target_compile_features(utreexo_rpc_tests PRIVATE cxx_std_20)
        utreexo_configure_target(utreexo_rpc_tests)
        add_test(NAME utreexo_rpc_tests COMMAND utreexo_rpc_tests)

        add_test(NAME utreexo_cli_path_validation_tests
            COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/test/cli_path_validation_tests.sh
                $<TARGET_FILE:utreexo-bridge>)
        set_tests_properties(utreexo_cli_path_validation_tests PROPERTIES TIMEOUT 30)

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

install(TARGETS utreexo-checkpoint-compact
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
if(UTREEXO_BUILD_BENCHMARKS)
    install(TARGETS utreexo-resource-estimate
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
if(UTREEXO_BUILD_RPC)
    install(TARGETS utreexo-bridge
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
install(FILES README.md CHANGELOG.md SECURITY.md LICENSE MAINNET_SYNC_READINESS.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES third_party/univalue/COPYING
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    RENAME LICENSE.univalue)
install(FILES contrib/checkpoints/mainnet-943013.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/utreexo-bridge/checkpoints)
if(UTREEXO_BUILD_RPC)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/utreexo-bridge.service
        contrib/systemd/utreexo-bridge.conf.example
        DESTINATION ${CMAKE_INSTALL_DATADIR}/utreexo-bridge/systemd)
endif()
install(FILES contrib/tor/torrc.example contrib/tor/bitcoin.conf.example
    DESTINATION ${CMAKE_INSTALL_DATADIR}/utreexo-bridge/tor)
install(FILES doc/tor.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR})

set(CPACK_PACKAGE_NAME "utreexo-bridge")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME
    "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_GENERATOR "TGZ")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY ON)
set(CPACK_PACKAGE_CHECKSUM "SHA256")
include(CPack)
