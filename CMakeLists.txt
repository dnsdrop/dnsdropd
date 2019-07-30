cmake_minimum_required (VERSION 2.8)
project                (csos-init)
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

if (NOT EXISTS ${PROJECT_BINARY_DIR}/thirdparty.cmake)
    message(FATAL_ERROR
            "RUN THIS FIRST:\ncd ${PROJECT_SOURCE_DIR}\n./bootstrap.sh\ncd ${PROJECT_BINARY_DIR}")
endif()

find_package         (OpenSSL REQUIRED)

include              (CheckIncludeFiles)
include              (${PROJECT_BINARY_DIR}/thirdparty.cmake)

check_include_files  (sys/tree.h  HAVE_SYS_TREE)
check_include_files  (sys/queue.h HAVE_SYS_QUEUE)

if (NOT HAVE_SYS_TREE)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/sys/tree.h.in
        ${PROJECT_BINARY_DIR}/include/sys/tree.h)
endif()

if (NOT HAVE_SYS_QUEUE)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/sys/queue.h.in
        ${PROJECT_BINARY_DIR}/include/sys/queue.h)
endif()

include_directories  (${OPENSSL_INCLUDE_DIRS})
include_directories  (${PROJECT_BINARY_DIR}/include)
include_directories  (${CMAKE_SOURCE_DIR}/src)
link_directories     (${PROJECT_BINARY_DIR}/lib)

add_subdirectory(src)
add_subdirectory(examples)
