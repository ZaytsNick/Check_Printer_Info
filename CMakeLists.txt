cmake_minimum_required(VERSION 3.15)

project(CheckPrinterInfo LANGUAGES CXX)
multithreaded sending of snmp request
# Пути к библиотекам и заголовкам Net-SNMP
include_directories(/usr/include/net-snmp)
link_directories(/usr/lib)

# Основной исполняемый файл
add_executable(CheckPrinterInfo main.cpp)

# Подключение библиотек
target_link_libraries(CheckPrinterInfo PRIVATE netsnmp ssl crypto)#folly::folly)
    