cmake_minimum_required(VERSION 4.1)
project(sniper)

set(CMAKE_CXX_STANDARD 20)
enable_testing()
option(SNIPER_ENABLE_LIVE_FUNCTIONAL_TESTS "Enable live PostgreSQL + eBPF functional tests" OFF)

set(BPF_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/pg_probe.bpf.o)
set(LIBBPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libbpf)
set(LIBBPF_SRC_DIR ${LIBBPF_DIR}/src)
set(LIBBPF_A ${LIBBPF_SRC_DIR}/libbpf.a)

add_custom_command(
    OUTPUT ${BPF_OBJECT}
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c
            ${CMAKE_CURRENT_SOURCE_DIR}/pg_probe.bpf.c
            -I${CMAKE_CURRENT_SOURCE_DIR}
            -I${LIBBPF_SRC_DIR}
            -I/usr/include
            -I/usr/include/bpf
            -o ${BPF_OBJECT}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/pg_probe.bpf.c ${CMAKE_CURRENT_SOURCE_DIR}/vmlinux.h
    COMMENT "Building eBPF object pg_probe.bpf.o"
    VERBATIM
)

add_custom_target(pg_probe_bpf ALL DEPENDS ${BPF_OBJECT})

add_custom_command(
    OUTPUT ${LIBBPF_A}
    COMMAND ${CMAKE_COMMAND} -E env
            PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig
            make -C ${LIBBPF_SRC_DIR} BUILD_STATIC_ONLY=y
    WORKING_DIRECTORY ${LIBBPF_SRC_DIR}
    COMMENT "Building static libbpf.a"
    VERBATIM
)

add_custom_target(libbpf_static ALL DEPENDS ${LIBBPF_A})

add_library(sniper_trace_runtime STATIC pg_trace_session.cpp)
target_include_directories(sniper_trace_runtime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sniper main.cpp pg_probe.cpp)

target_include_directories(sniper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBBPF_SRC_DIR}
    ${LIBBPF_DIR}/include/uapi
    /usr/include
)
target_link_libraries(sniper PRIVATE sniper_trace_runtime ${LIBBPF_A} elf z)

add_dependencies(sniper pg_probe_bpf)
add_dependencies(sniper libbpf_static)

add_executable(sniper_functional_tests
    tests/functional/pg_trace_session_test.cpp
)
target_link_libraries(sniper_functional_tests PRIVATE sniper_trace_runtime)
target_include_directories(sniper_functional_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME sniper_functional_tests COMMAND sniper_functional_tests)

if(SNIPER_ENABLE_LIVE_FUNCTIONAL_TESTS)
    add_test(
        NAME sniper_live_functional_test
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/tests/functional/run_live_functional_test.sh $<TARGET_FILE:sniper>
    )
    set_tests_properties(sniper_live_functional_test PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        SKIP_RETURN_CODE 77
    )
endif()
