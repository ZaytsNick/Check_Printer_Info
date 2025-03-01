cmake_minimum_required(VERSION 3.10)
project(CheckPrinterInfo)

# Указываем стандарт C++ (например, C++17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(BUILD_SHARED_LIBS OFF) 

# Найдем библиотеки Prometheus
find_library(PROMETHEUS1_LIBRARY libprometheus-cpp-pull.a PATHS ${CMAKE_SOURCE_DIR}/libs)
find_library(PROMETHEUS2_LIBRARY libprometheus-cpp-push.a PATHS ${CMAKE_SOURCE_DIR}/libs)
find_library(PROMETHEUS3_LIBRARY libprometheus-cpp-core.a PATHS ${CMAKE_SOURCE_DIR}/libs)

# Найдем статические библиотеки SNMP
find_library(SNMP_STATIC1_LIBRARY libnetsnmp.a PATHS /usr/local/lib/)
find_library(SNMP_STATIC2_LIBRARY libnetsnmpagent.a PATHS /usr/local/lib/)
find_library(SNMP_STATIC3_LIBRARY libnetsnmphelpers.a PATHS /usr/local/lib/)

# Найдем OpenSSL через pkg-config

# Указываем путь к MIB-файлам
# set(MIB_PATHS "${CMAKE_SOURCE_DIR}/mibs")

# file(GLOB MIB_FILES ${MIB_PATHS}/*.txt)

# Добавляем исполняемый файл
add_executable(CheckPrinterInfo main.cpp)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

target_sources(CheckPrinterInfo PRIVATE ${MIB_FILES})

# add_compile_options(-fno-builtin-memcpy)
    target_link_libraries(CheckPrinterInfo PRIVATE    
    -static
    # -L/usr/lib
    # -L/usr/local/lib64
    # ${SNMP_STATIC1_LIBRARY}
    # ${SNMP_STATIC2_LIBRARY}
    # ${SNMP_STATIC3_LIBRARY}
    /usr/local/net-snmp/lib/libnetsnmp.a
    /usr/local/net-snmp/lib/libnetsnmpagent.a
    /usr/local/net-snmp/lib/libnetsnmphelpers.a

    # ${PROMETHEUS1_LIBRARY}
    # ${PROMETHEUS2_LIBRARY}
    # ${PROMETHEUS3_LIBRARY}
    /usr/local/lib/libprometheus-cpp-pull.a
    /usr/local/lib/libprometheus-cpp-push.a
    /usr/local/lib/libprometheus-cpp-core.a


        # /usr/lib/libssl.a
        # /usr/local/lib64/libcrypto.a
    /usr/local/openssl/lib/libssl.a       # Статическая библиотека SSL
    /usr/local/openssl/lib/libcrypto.a    # Статическая библиотека Crypto
        -static-libgcc
        -static-libstdc++
        stdc++fs
        # -lz
        /usr/lib/libz.a
        # -lm
        # /usr/lib/musl/lib/libm.a
        # -lc
        # /usr/lib/musl/lib/libc.a

    )

# Копируем файл конфигурации
configure_file(ipLists.json ${CMAKE_BINARY_DIR}/ipLists.json COPYONLY)





# Найдем OpenSSL через pkg-config
# find_package(PkgConfig REQUIRED)
# pkg_search_module(OPENSSL REQUIRED openssl)

# if (OPENSSL_FOUND)
#     message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
#     message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIRS}")
#     message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
# else()
#     message(FATAL_ERROR "OpenSSL not found!")
# endif()

# include_directories(${OPENSSL_INCLUDE_DIRS})
# link_directories(${OPENSSL_LIBRARY_DIRS})



# cmake_minimum_required(VERSION 3.10)
# project(CheckPrinterInfo)

# # Указываем стандарт C++ (например, C++17)
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED True)

# find_library(PROMETHEUS1_LIBRARY libprometheus-cpp-pull.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS2_LIBRARY libprometheus-cpp-push.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS3_LIBRARY libprometheus-cpp-core.a PATHS ${CMAKE_SOURCE_DIR}/libs)

# find_library(SNMP_STATIC1_LIBRARY libnetsnmp.a PATHS /usr/local/lib/)
# find_library(SNMP_STATIC2_LIBRARY libnetsnmpagent.a PATHS /usr/local/lib/)
# find_library(SNMP_STATIC3_LIBRARY libnetsnmphelpers.a PATHS /usr/local/lib/)

# find_package(PkgConfig REQUIRED)
# pkg_search_module(OPENSSL REQUIRED openssl)

# if (OPENSSL_FOUND)
#     message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
#     message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIRS}")
#     message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
# else()
#     message(FATAL_ERROR "OpenSSL not found!")
# endif()

# include_directories(${OPENSSL_INCLUDE_DIRS})
# link_directories(${OPENSSL_LIBRARY_DIRS})
# # Указываем путь к MIB-файлам
# # file(GLOB MIB_FILES "/usr/share/snmp/mibs/*.txt")
# # foreach(MIB_FILE ${MIB_FILES})
# # configure_file(${MIB_FILE} ${CMAKE_BINARY_DIR}/mibs/ COPYONLY)
# # endforeach()
# # set(MIB_HEADER_FILE "${CMAKE_SOURCE_DIR}/mib_files.h")
# # Указываем каталоги для поиска MIB-файлов
# set(MIB_PATHS "${CMAKE_SOURCE_DIR}/mibs")

# # Настроим переменные окружения для поиска MIB
# set(ENV{MIBDIRS} "${MIB_PATHS}")
# # Добавляем исполняемый файл
# add_executable(CheckPrinterInfo main.cpp)
# # Статическая линковка стандартной библиотеки и stdc++fs
# if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
#     target_link_libraries(CheckPrinterInfo PRIVATE 

#         ${SNMP_STATIC1_LIBRARY}
#         ${SNMP_STATIC2_LIBRARY}
#         ${SNMP_STATIC3_LIBRARY}
    
#         ${PROMETHEUS1_LIBRARY}
#         ${PROMETHEUS2_LIBRARY}
#         ${PROMETHEUS3_LIBRARY}

#         # ${SSL_LIBRARY}
#         # ${CRYPTO_LIBRARY}
#         # ${M}
#         # ${C}

#         /usr/lib/libssl.a
#         /usr/local/lib64/libcrypto.a
#         /usr/lib/libm.a
#         /usr/lib/libc.a
    
#         -L/usr/lib
#         -L/usr/local/lib64
    
#         -static-libgcc
#         -static-libstdc++
#         stdc++fs
#         -lz
#         -lm
#         -lc
#     )
#     elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
#         set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
#     endif()

# configure_file(ipLists.json ${CMAKE_BINARY_DIR}/ipLists.json COPYONLY)








#     /usr/local/lib64/libcrypto.a
#     /usr/lib/libssl.a
#     # /usr/lib/libz.a
#     # /usr/lib/libm.a
#     # /usr/lib/libc.a
    
#     -static-libgcc 
#     -static-libstdc++ 
#     stdc++fs
#     -lz
#     /usr/lib/libm.a
# /usr/lib/libc.a




# cmake_minimum_required(VERSION 3.10)
# project(CheckPrinterInfo)

# # Указываем, что хотим использовать статические библиотеки
# set(BUILD_SHARED_LIBS OFF)

# # Добавляем пути к статическим библиотекам
# # set(CMAKE_PREFIX_PATH "/path/to/your/static/libs")
# set(CMAKE_PREFIX_PATH "/usr/local/lib" "/usr/lib" "/home/zaytsnick/Downloads/net-snmp-5.8")

# # Находим необходимые библиотеки
# find_package(nlohmann_json REQUIRED)
# find_package(prometheus-cpp REQUIRED)
# find_package(NetSNMP REQUIRED)
# # find_package(net-snmp REQUIRED)

# # Добавляем исполняемый файл
# add_executable(CheckPrinterInfo main.cpp)

# find_path(NetSNMP_INCLUDE_DIR net-snmp/net-snmp-config.h)

# # Линкуем библиотеки к нашему исполняемому файлу
# target_link_libraries(CheckPrinterInfo
#     nlohmann_json::nlohmann_json
#     prometheus-cpp::core
#     prometheus-cpp::exposer
#     NetSNMP::agent
#     NetSNMP::helpers
#     NetSNMP::mibs
#     NetSNMP::snmptrapd
#     NetSNMP::netsnmp
#     # netsnmp
# )

# # Указываем, что нужно использовать статическую линковку для стандартных библиотек
# if (WIN32)
#     set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MT")
# else()
#     set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
# endif()

# configure_file(ipLists.json ${CMAKE_BINARY_DIR}/ipLists.json COPYONLY)










# cmake_minimum_required(VERSION 3.15)

# project(CheckPrinterInfo LANGUAGES CXX)

# set(BUILD_SHARED_LIBS OFF) 

# # Путь к библиотекам
# include_directories(/usr/include/net-snmp)
# link_directories(/usr/lib)

# find_library(ZLIB_STATIC_LIBRARY      libz.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(CRYPTO_STATIC_LIBRARY    libcrypto.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SSL_STATIC_LIBRARY       libssl.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SNMP_STATIC1_LIBRARY     libnetsnmp.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SNMP_STATIC2_LIBRARY     libnetsnmpagent.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SNMP_STATIC3_LIBRARY     libnetsnmphelpers.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS1_LIBRARY      libprometheus-cpp-pull.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS2_LIBRARY      libprometheus-cpp-push.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS3_LIBRARY      libprometheus-cpp-core.a PATHS ${CMAKE_SOURCE_DIR}/libs)

# # Поиск библиотеки prometheus-cpp
# find_package(prometheus-cpp CONFIG REQUIRED)
# find_package(nlohmann_json REQUIRED)
# # Создание исполняемого файла
# add_executable(CheckPrinterInfo main.cpp)

# # Указание директорий и библиотек для линковки
# target_include_directories(CheckPrinterInfo PRIVATE /usr/include/net-snmp)
# target_link_libraries(CheckPrinterInfo PRIVATE 
#     # ${SNMP_STATIC1_LIBRARY}
#     # ${SNMP_STATIC2_LIBRARY}
#     # ${SNMP_STATIC3_LIBRARY}
#     ${ZLIB_STATIC_LIBRARY}
#     ${CRYPTO_STATIC_LIBRARY}
#     ${SSL_STATIC_LIBRARY}
#     # ${PROMETHEUS1_LIBRARY}
#     # ${PROMETHEUS2_LIBRARY}
#     # ${PROMETHEUS3_LIBRARY}
#     netsnmp
#     # ssl 
#     # crypto 
#     prometheus-cpp::pull 
#     nlohmann_json::nlohmann_json
#     )

# # Копирование конфигурационного файла
# configure_file(ipLists.json ${CMAKE_BINARY_DIR}/ipLists.json COPYONLY)










# cmake_minimum_required(VERSION 3.15)
# set(CMAKE_CXX_STANDARD 17)
# set(CMAKE_CXX_STANDARD_REQUIRED ON)

# # Проект
# project(CheckPrinterInfo LANGUAGES CXX)

# # Указываем, что хотим статическую компоновку
# set(BUILD_SHARED_LIBS OFF)  # Отключаем сборку динамических библиотек
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libstdc++ -static-libgcc")
# set(CMAKE_C_COMPILER /usr/bin/clang)

# # Пути к библиотекам
# include_directories(${CMAKE_SOURCE_DIR}/libs /usr/include/net-snmp)
# link_directories(${CMAKE_SOURCE_DIR}/libs ${CMAKE_SOURCE_DIR}/include /usr/lib)
# # include_directories()

# # Поиск статических библиотек
# find_library(ZLIB_STATIC_LIBRARY libz.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(CRYPTO_STATIC_LIBRARY libcrypto.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SSL_STATIC_LIBRARY libssl.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SNMP_STATIC1_LIBRARY libnetsnmp.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SNMP_STATIC2_LIBRARY libnetsnmpagent.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(SNMP_STATIC3_LIBRARY libnetsnmphelpers.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS1_LIBRARY libprometheus-cpp-pull.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS2_LIBRARY libprometheus-cpp-push.a PATHS ${CMAKE_SOURCE_DIR}/libs)
# find_library(PROMETHEUS3_LIBRARY libprometheus-cpp-core.a PATHS ${CMAKE_SOURCE_DIR}/libs)

# # Поиск библиотеки prometheus-cpp
# # find_package(prometheus-cpp CONFIG REQUIRED)
# find_package(nlohmann_json REQUIRED)

# # Создание исполняемого файла
# add_executable(CheckPrinterInfo main.cpp)

# # Указание директорий и библиотек для линковки
# target_include_directories(CheckPrinterInfo PRIVATE /usr/include/net-snmp)
# target_link_libraries(CheckPrinterInfo PRIVATE 
# ${SNMP_STATIC1_LIBRARY}
# ${SNMP_STATIC2_LIBRARY}
# ${SNMP_STATIC3_LIBRARY}
# ${ZLIB_STATIC_LIBRARY}
# ${CRYPTO_STATIC_LIBRARY}
# ${SSL_STATIC_LIBRARY}
# ${PROMETHEUS1_LIBRARY}
# ${PROMETHEUS2_LIBRARY}
# ${PROMETHEUS3_LIBRARY}
# pthread
# dl
# resolv
# )

# # Копирование конфигурационного файла
# configure_file(ipLists.json ${CMAKE_BINARY_DIR}/ipLists.json COPYONLY)