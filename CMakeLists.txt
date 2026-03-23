cmake_minimum_required(VERSION 4.1)
project(sniper)

set(CMAKE_CXX_STANDARD 20)

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

add_executable(sniper main.cpp pg_probe.cpp)

target_include_directories(sniper PRIVATE
    ${LIBBPF_SRC_DIR}
    ${LIBBPF_DIR}/include/uapi
    /usr/include
)
target_link_libraries(sniper PRIVATE ${LIBBPF_A} elf z)

add_dependencies(sniper pg_probe_bpf)
add_dependencies(sniper libbpf_static)
