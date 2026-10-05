cmake_minimum_required(VERSION 3.16)
project(openknx_management_policy_tests LANGUAGES C CXX)

enable_testing()

file(GLOB behavioral_sources CONFIGURE_DEPENDS ../src/knx/*.cpp)
list(FILTER behavioral_sources EXCLUDE REGEX "/(bau07B0|bau091A|bau2920|tpuart_data_link_layer)\\.cpp$")
add_library(behavioral_core STATIC ${behavioral_sources})
target_compile_features(behavioral_core PUBLIC cxx_std_14)
target_compile_definitions(behavioral_core PUBLIC MASK_VERSION=0x07B0 NO_KNX_CONFIG KNX_NO_PRINT KNX_FLASH_SIZE=4096)
set(TPUART_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../OpenKNX-tpuart" CACHE PATH "TPUART source checkout")
target_include_directories(behavioral_core PUBLIC ../src "${TPUART_SOURCE_DIR}/src")
add_executable(behavioral_test behavioral_test.cpp)
target_link_libraries(behavioral_test PRIVATE behavioral_core)
option(ENABLE_SANITIZERS "Run behavioral tests with ASan and UBSan" OFF)
if(ENABLE_SANITIZERS)
    foreach(target behavioral_core behavioral_test)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address,undefined)
        # Container ASLR/PIE can crash libasan before its initialization/main.
        # Keep Linux sanitizer fixtures non-PIE for reproducible diagnostics;
        # this does not change firmware or normal host-build flags.
        if(UNIX AND NOT APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE -fno-pie)
            target_link_options(${target} PRIVATE -no-pie)
        endif()
    endforeach()
endif()
add_test(NAME behavioral_test COMMAND behavioral_test)

# Secure variants compile and link the actual implementation, including AES C.
# Host asymmetric primitives use the independently maintained OpenSSL backend.
find_package(OpenSSL REQUIRED)
foreach(secure_variant device ip)
    add_library(secure_${secure_variant}_core STATIC ${behavioral_sources} ../src/knx/aes.c)
    target_compile_features(secure_${secure_variant}_core PUBLIC cxx_std_14)
    target_compile_definitions(secure_${secure_variant}_core PUBLIC
        NO_KNX_CONFIG KNX_NO_PRINT KNX_FLASH_SIZE=16384 USE_DATASECURE KNX_SECURE_OPENSSL)
    if(secure_variant STREQUAL "device")
        target_compile_definitions(secure_${secure_variant}_core PUBLIC MASK_VERSION=0x07B0)
    else()
        target_compile_definitions(secure_${secure_variant}_core PUBLIC
            MASK_VERSION=0x091A USE_IP=1 USE_TP=1 USE_CEMI_SERVER=1 USE_IPSECURE KNX_TUNNELING=1 KNX_SERVICE_FAMILY_CORE=2)
    endif()
    target_include_directories(secure_${secure_variant}_core PUBLIC ../src "${TPUART_SOURCE_DIR}/src" stubs)
    target_compile_options(secure_${secure_variant}_core PUBLIC
        "$<$<COMPILE_LANGUAGE:CXX>:-include>" "$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_SOURCE_DIR}/stubs/host_network_compat.h>")
    target_link_libraries(secure_${secure_variant}_core PUBLIC OpenSSL::Crypto)
    if(ENABLE_SANITIZERS)
        target_compile_options(secure_${secure_variant}_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(secure_${secure_variant}_core PUBLIC -fsanitize=address,undefined)
        if(UNIX AND NOT APPLE AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(secure_${secure_variant}_core PUBLIC -fno-pie)
            target_link_options(secure_${secure_variant}_core PUBLIC -no-pie)
        endif()
    endif()
endforeach()
foreach(secure_test security_state data_secure secure_proxy ip_secure)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${secure_test}_test.cpp")
        add_executable(${secure_test}_test ${secure_test}_test.cpp)
        if(NOT secure_test STREQUAL "ip_secure")
            target_link_libraries(${secure_test}_test PRIVATE secure_device_core)
        else()
            target_link_libraries(${secure_test}_test PRIVATE secure_ip_core)
        endif()
        add_test(NAME ${secure_test}_test COMMAND ${secure_test}_test)
    endif()
endforeach()
add_executable(secure_proxy_ip_test secure_proxy_test.cpp)
target_link_libraries(secure_proxy_ip_test PRIVATE secure_ip_core)
add_test(NAME secure_proxy_ip_test COMMAND secure_proxy_ip_test)

# These are object targets on purpose: OpenKNX does not currently provide a
# linkable native-host platform implementation.  They still compile the real
# headers and hardened implementation units, including all static assertions.
add_library(management_policy_compile OBJECT management_policy_test.cpp)
target_compile_features(management_policy_compile PRIVATE cxx_std_14)
target_compile_definitions(management_policy_compile PRIVATE MASK_VERSION=0x07B0)
target_include_directories(management_policy_compile PRIVATE ../src)

add_library(application_layer_hardening_compile OBJECT
    ../src/knx/application_layer.cpp
    ../src/knx/npdu.cpp
)
target_compile_features(application_layer_hardening_compile PRIVATE cxx_std_14)
target_compile_definitions(application_layer_hardening_compile PRIVATE MASK_VERSION=0x07B0)
target_include_directories(application_layer_hardening_compile PRIVATE ../src)

add_library(router_hardening_compile OBJECT
    ../src/knx/router_object.cpp
    ../src/knx/rf_medium_object.cpp
)
target_compile_features(router_hardening_compile PRIVATE cxx_std_14)
target_compile_definitions(router_hardening_compile PRIVATE MASK_VERSION=0x27B0)
target_include_directories(router_hardening_compile PRIVATE
    stubs
    ../src
)

add_library(rf_data_link_hardening_compile OBJECT
    ../src/knx/rf_data_link_layer.cpp
    ../src/knx/rf_physical_layer_cc1101.cpp
)
target_compile_features(rf_data_link_hardening_compile PRIVATE cxx_std_14)
target_compile_definitions(rf_data_link_hardening_compile PRIVATE
    MASK_VERSION=0x27B0
    USE_RF=1
)
target_include_directories(rf_data_link_hardening_compile PRIVATE
    stubs
    ../src
)

add_library(cemi_ip_hardening_compile OBJECT
    ../src/knx/cemi_frame.cpp
    ../src/knx/cemi_server.cpp
    ../src/knx/ip_parameter_object.cpp
    ../src/knx/ip_tunnel_server.cpp
    ../src/knx/knx_ip_tunneling_request.cpp
)
target_compile_features(cemi_ip_hardening_compile PRIVATE cxx_std_14)
target_compile_definitions(cemi_ip_hardening_compile PRIVATE
    MASK_VERSION=0x57B0
    KNX_TUNNELING=1
)
target_compile_options(cemi_ip_hardening_compile PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/stubs/host_network_compat.h"
)
target_include_directories(cemi_ip_hardening_compile PRIVATE
    stubs
    ../src
)

add_library(cemi_usb_hardening_compile OBJECT
    ../src/knx/cemi_frame.cpp
    ../src/knx/cemi_server.cpp
    ../src/knx/usb_tunnel_interface.cpp
)
target_compile_features(cemi_usb_hardening_compile PRIVATE cxx_std_14)
target_compile_definitions(cemi_usb_hardening_compile PRIVATE
    MASK_VERSION=0x07B0
    USE_USB=1
)
target_include_directories(cemi_usb_hardening_compile PRIVATE
    stubs
    ../src
)

add_library(ip_core_hardening_compile OBJECT
    ../src/knx/ip_data_link_layer.cpp
    ../src/knx/knx_ip_routing_indication.cpp
    ../src/knx/knx_ip_search_request_extended.cpp
    ../src/knx/knx_ip_search_response_extended.cpp
)
target_compile_features(ip_core_hardening_compile PRIVATE cxx_std_14)
target_compile_definitions(ip_core_hardening_compile PRIVATE
    MASK_VERSION=0x57B0
    KNX_TUNNELING=1
    KNX_SERVICE_FAMILY_CORE=2
)
target_compile_options(ip_core_hardening_compile PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/stubs/host_network_compat.h"
)
target_include_directories(ip_core_hardening_compile PRIVATE
    stubs
    ../src
)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(
    NAME hardening_source_contract
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/hardening_source_contract_test.py"
)
