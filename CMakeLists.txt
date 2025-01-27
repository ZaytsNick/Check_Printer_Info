cmake_minimum_required(VERSION 3.15)

project(CheckPrinterInfo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Пути к библиотекам и заголовкам Net-SNMP
include_directories(/usr/include/net-snmp)
link_directories(/usr/lib)

# Основной исполняемый файл
add_executable(CheckPrinterInfo main.cpp)

# Подключение библиотек
target_link_libraries(CheckPrinterInfo PRIVATE netsnmp ssl crypto)
    