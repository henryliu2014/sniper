#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

enum event_type : uint32_t {
    EVENT_TYPE_IO = 1,
    EVENT_TYPE_PHASE = 2,
    EVENT_TYPE_OPERATOR = 3,
    EVENT_TYPE_SEQ_SCAN_STEP = 4,
    EVENT_TYPE_LWLOCK_WAIT = 5,
};

enum query_phase : uint8_t {
    QUERY_PHASE_PARSE = 1,
    QUERY_PHASE_ANALYZE = 2,
    QUERY_PHASE_PLAN = 3,
    QUERY_PHASE_EXECUTE = 4,
};

enum io_direction : uint8_t {
    IO_DIRECTION_IN = 0,
    IO_DIRECTION_OUT = 1,
};

struct event_header {
    uint32_t type;
};

struct read_event {
    uint32_t type;
    uint64_t ts_ns;
    uint32_t pid;
    uint32_t tid;
    int32_t fd;
    int64_t count;
    int32_t len;
    uint8_t direction;
    char comm[16];
    unsigned char data[4096];
};

struct phase_event {
    uint32_t type;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t pid;
    uint32_t tid;
    uint8_t phase;
    char comm[16];
};

struct operator_event {
    uint32_t type;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t pid;
    uint32_t tid;
    uint16_t op_id;
    uint16_t depth;
    char comm[16];
};

struct seq_scan_step_event {
    uint32_t type;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t pid;
    uint32_t tid;
    uint8_t step_id;
    uint8_t seq_scan_depth;
    char comm[16];
};

struct lwlock_wait_event {
    uint32_t type;
    uint64_t start_ns;
    uint64_t end_ns;
    uint32_t pid;
    uint32_t tid;
    uint16_t op_id;
    uint16_t op_depth;
    uint8_t step_id;
    uint8_t step_depth;
    char comm[16];
};

class PgTraceSession {
public:
    void set_realtime_offset_ns(uint64_t realtime_offset_ns);
    int handle_event(const void* data, size_t data_sz);
    std::vector<std::string> take_completed_queries();

private:
    struct impl;
    impl* impl_ = nullptr;

public:
    PgTraceSession();
    ~PgTraceSession();
    PgTraceSession(const PgTraceSession&) = delete;
    PgTraceSession& operator=(const PgTraceSession&) = delete;
    PgTraceSession(PgTraceSession&&) noexcept;
    PgTraceSession& operator=(PgTraceSession&&) noexcept;
};
