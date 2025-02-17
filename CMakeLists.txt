cmake_minimum_required(VERSION 3.15)

project(CheckPrinterInfo LANGUAGES CXX)

include(FetchContent)

FetchContent_Declare(
        json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)

include_directories(/usr/include/net-snmp)
link_directories(/usr/lib)

project(prometheus-cpp-import)

find_package(prometheus-cpp CONFIG REQUIRED)

add_executable(CheckPrinterInfo main.cpp)

target_include_directories(CheckPrinterInfo PRIVATE ${INCLUDE_DIR})
target_link_libraries(CheckPrinterInfo PRIVATE netsnmp ssl crypto prometheus-cpp::pull nlohmann_json::nlohmann_json)#prometheus)#folly::folly)
    

configure_file(ipLists.json ${CMAKE_BINARY_DIR}/ipLists.json COPYONLY)