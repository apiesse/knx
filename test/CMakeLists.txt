cmake_minimum_required(VERSION 3.16)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
project(openknx_management_policy_tests LANGUAGES CXX)

enable_testing()

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
