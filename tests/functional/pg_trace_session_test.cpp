#include "pg_trace_session.h"

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {
template <size_t N>
std::string_view literal_view(const char (&text)[N]) {
    return std::string_view(text, N - 1);
}

[[noreturn]] void fail(const std::string& message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void expect(bool condition, const std::string& message) {
    if (!condition) {
        fail(message);
    }
}

void expect_contains(std::string_view haystack, std::string_view needle) {
    if (haystack.find(needle) == std::string_view::npos) {
        fail("missing substring: " + std::string(needle));
    }
}

std::vector<unsigned char> typed_message(unsigned char tag, std::string_view payload) {
    const uint32_t len = static_cast<uint32_t>(payload.size() + 4);
    std::vector<unsigned char> bytes;
    bytes.reserve(payload.size() + 5);
    bytes.push_back(tag);
    bytes.push_back(static_cast<unsigned char>((len >> 24) & 0xff));
    bytes.push_back(static_cast<unsigned char>((len >> 16) & 0xff));
    bytes.push_back(static_cast<unsigned char>((len >> 8) & 0xff));
    bytes.push_back(static_cast<unsigned char>(len & 0xff));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

read_event make_read_event(uint32_t pid, int fd, uint8_t direction, uint64_t ts_ns,
                           const std::vector<unsigned char>& payload) {
    read_event event{};
    event.type = EVENT_TYPE_IO;
    event.pid = pid;
    event.tid = pid;
    event.fd = fd;
    event.direction = direction;
    event.ts_ns = ts_ns;
    event.len = static_cast<int32_t>(payload.size());
    event.count = static_cast<int64_t>(payload.size());
    std::memcpy(event.comm, "postgres", 8);
    std::memcpy(event.data, payload.data(), payload.size());
    return event;
}

phase_event make_phase_event(uint32_t pid, uint32_t tid, uint8_t phase, uint64_t start_ns, uint64_t end_ns) {
    phase_event event{};
    event.type = EVENT_TYPE_PHASE;
    event.pid = pid;
    event.tid = tid;
    event.phase = phase;
    event.start_ns = start_ns;
    event.end_ns = end_ns;
    return event;
}

operator_event make_operator_event(uint32_t pid, uint32_t tid, uint16_t op_id, uint16_t depth,
                                   uint64_t start_ns, uint64_t end_ns) {
    operator_event event{};
    event.type = EVENT_TYPE_OPERATOR;
    event.pid = pid;
    event.tid = tid;
    event.op_id = op_id;
    event.depth = depth;
    event.start_ns = start_ns;
    event.end_ns = end_ns;
    return event;
}

seq_scan_step_event make_step_event(uint32_t pid, uint32_t tid, uint8_t step_id, uint8_t depth,
                                    uint64_t start_ns, uint64_t end_ns) {
    seq_scan_step_event event{};
    event.type = EVENT_TYPE_SEQ_SCAN_STEP;
    event.pid = pid;
    event.tid = tid;
    event.step_id = step_id;
    event.seq_scan_depth = depth;
    event.start_ns = start_ns;
    event.end_ns = end_ns;
    return event;
}

lwlock_wait_event make_wait_event(uint32_t pid, uint32_t tid, uint16_t op_id, uint16_t op_depth,
                                  uint8_t step_id, uint8_t step_depth, uint64_t start_ns, uint64_t end_ns) {
    lwlock_wait_event event{};
    event.type = EVENT_TYPE_LWLOCK_WAIT;
    event.pid = pid;
    event.tid = tid;
    event.op_id = op_id;
    event.op_depth = op_depth;
    event.step_id = step_id;
    event.step_depth = step_depth;
    event.start_ns = start_ns;
    event.end_ns = end_ns;
    return event;
}

std::string take_single_output(PgTraceSession& session) {
    std::vector<std::string> out = session.take_completed_queries();
    expect(out.size() == 1, "expected one completed query");
    return out.front();
}

void test_simple_query_batch_with_sql_splitting() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    const auto frontend = typed_message('Q', literal_view("select ';' as semi; select 2; -- keep ; inside comment\n\0"));
    auto frontend_event = make_read_event(101, 9, IO_DIRECTION_IN, 1'000'000'000ull, frontend);
    expect(session.handle_event(&frontend_event, sizeof(frontend_event)) == 0, "frontend parse failed");

    const auto command_complete = typed_message('C', literal_view("SELECT 1\0"));
    const auto ready_for_query = typed_message('Z', literal_view("I"));
    auto backend_complete = make_read_event(101, 9, IO_DIRECTION_OUT, 2'000'000'000ull, command_complete);
    auto backend_ready = make_read_event(101, 9, IO_DIRECTION_OUT, 3'000'000'000ull, ready_for_query);

    expect(session.handle_event(&backend_complete, sizeof(backend_complete)) == 0, "backend complete failed");
    std::string first = take_single_output(session);
    expect_contains(first, "QUERY\n");
    expect_contains(first, "sql: select ';' as semi");

    expect(session.handle_event(&backend_complete, sizeof(backend_complete)) == 0, "second complete failed");
    std::string second = take_single_output(session);
    expect_contains(second, "sql: select 2");

    expect(session.handle_event(&backend_ready, sizeof(backend_ready)) == 0, "ready for query failed");
    expect(session.take_completed_queries().empty(), "ready-for-query should not emit a new query");
}

void test_extended_protocol_execute_uses_prepared_sql() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    const auto parse = typed_message('P', literal_view("stmt1\0select 42\0\0\0"));
    const auto bind = typed_message('B', literal_view("portal1\0stmt1\0\0\0\0\0"));
    const auto execute = typed_message('E', literal_view("portal1\0\0\0\0"));
    auto parse_event = make_read_event(202, 12, IO_DIRECTION_IN, 10'000ull, parse);
    auto bind_event = make_read_event(202, 12, IO_DIRECTION_IN, 20'000ull, bind);
    auto execute_event = make_read_event(202, 12, IO_DIRECTION_IN, 30'000ull, execute);

    expect(session.handle_event(&parse_event, sizeof(parse_event)) == 0, "parse message failed");
    expect(session.handle_event(&bind_event, sizeof(bind_event)) == 0, "bind message failed");
    expect(session.handle_event(&execute_event, sizeof(execute_event)) == 0, "execute message failed");

    const auto parse_complete = typed_message('1', std::string_view());
    const auto portal_suspend = typed_message('s', std::string_view());
    auto parse_complete_event = make_read_event(202, 12, IO_DIRECTION_OUT, 40'000ull, parse_complete);
    auto portal_suspend_event = make_read_event(202, 12, IO_DIRECTION_OUT, 50'000ull, portal_suspend);

    expect(session.handle_event(&parse_complete_event, sizeof(parse_complete_event)) == 0, "parse complete response failed");
    std::string prepare_out = take_single_output(session);
    expect_contains(prepare_out, "PREPARE\n");
    expect_contains(prepare_out, "sql: select 42");

    expect(session.handle_event(&portal_suspend_event, sizeof(portal_suspend_event)) == 0, "execute complete response failed");
    std::string execute_out = take_single_output(session);
    expect_contains(execute_out, "EXECUTE\n");
    expect_contains(execute_out, "sql: select 42");
}

void test_chunked_frontend_message_reconstructs_large_sql() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    std::string sql = "select ";
    sql.append(5000, 'x');
    sql += " from t";

    std::string payload(sql);
    payload.push_back('\0');
    const auto frontend = typed_message('Q', payload);

    std::vector<unsigned char> first_chunk(frontend.begin(), frontend.begin() + 4096);
    std::vector<unsigned char> second_chunk(frontend.begin() + 4096, frontend.end());

    auto frontend_event_1 = make_read_event(250, 18, IO_DIRECTION_IN, 1'000ull, first_chunk);
    auto frontend_event_2 = make_read_event(250, 18, IO_DIRECTION_IN, 2'000ull, second_chunk);

    expect(session.handle_event(&frontend_event_1, sizeof(frontend_event_1)) == 0, "first chunk parse failed");
    expect(session.handle_event(&frontend_event_2, sizeof(frontend_event_2)) == 0, "second chunk parse failed");

    const auto command_complete = typed_message('C', literal_view("SELECT 1\0"));
    auto backend_complete = make_read_event(250, 18, IO_DIRECTION_OUT, 3'000ull, command_complete);
    expect(session.handle_event(&backend_complete, sizeof(backend_complete)) == 0, "large query completion failed");

    std::string output = take_single_output(session);
    expect_contains(output, "QUERY\n");
    expect_contains(output, sql);
}

void test_ready_for_query_flushes_simple_query_when_command_complete_is_missed() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    const auto frontend = typed_message('Q', literal_view("insert into t values (1)\0"));
    auto frontend_event = make_read_event(404, 21, IO_DIRECTION_IN, 1'000ull, frontend);
    expect(session.handle_event(&frontend_event, sizeof(frontend_event)) == 0, "frontend query failed");

    const auto ready_for_query = typed_message('Z', literal_view("I"));
    auto backend_ready = make_read_event(404, 21, IO_DIRECTION_OUT, 2'000ull, ready_for_query);
    expect(session.handle_event(&backend_ready, sizeof(backend_ready)) == 0, "ready for query failed");

    std::string output = take_single_output(session);
    expect_contains(output, "QUERY\n");
    expect_contains(output, "sql: insert into t values (1)");
}

void test_backend_messages_on_unconfirmed_fd_are_ignored() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    const auto backend_complete = typed_message('C', literal_view("INSERT 0 1\0"));
    auto stray_backend = make_read_event(505, 30, IO_DIRECTION_OUT, 1'000ull, backend_complete);
    expect(session.handle_event(&stray_backend, sizeof(stray_backend)) == 0, "stray backend event failed");
    expect(session.take_completed_queries().empty(), "stray backend traffic should not emit queries");

    const auto frontend = typed_message('Q', literal_view("insert into t values (2)\0"));
    auto frontend_event = make_read_event(505, 31, IO_DIRECTION_IN, 2'000ull, frontend);
    expect(session.handle_event(&frontend_event, sizeof(frontend_event)) == 0, "frontend query failed");

    const auto ready = typed_message('Z', literal_view("I"));
    auto backend_ready = make_read_event(505, 30, IO_DIRECTION_OUT, 3'000ull, ready);
    expect(session.handle_event(&backend_ready, sizeof(backend_ready)) == 0, "stray ready event failed");
    expect(session.take_completed_queries().empty(), "backend traffic on wrong fd should be ignored");
}

void test_same_pid_can_track_multiple_socket_fds() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    const auto frontend_a = typed_message('Q', literal_view("select 1\0"));
    const auto frontend_b = typed_message('Q', literal_view("select 2\0"));
    auto frontend_event_a = make_read_event(606, 41, IO_DIRECTION_IN, 1'000ull, frontend_a);
    auto frontend_event_b = make_read_event(606, 42, IO_DIRECTION_IN, 2'000ull, frontend_b);

    expect(session.handle_event(&frontend_event_a, sizeof(frontend_event_a)) == 0, "first frontend query failed");
    expect(session.handle_event(&frontend_event_b, sizeof(frontend_event_b)) == 0, "second frontend query failed");

    const auto complete = typed_message('C', literal_view("SELECT 1\0"));
    auto backend_complete_b = make_read_event(606, 42, IO_DIRECTION_OUT, 3'000ull, complete);
    auto backend_complete_a = make_read_event(606, 41, IO_DIRECTION_OUT, 4'000ull, complete);

    expect(session.handle_event(&backend_complete_b, sizeof(backend_complete_b)) == 0, "second socket completion failed");
    std::string second = take_single_output(session);
    expect_contains(second, "sql: select 2");

    expect(session.handle_event(&backend_complete_a, sizeof(backend_complete_a)) == 0, "first socket completion failed");
    std::string first = take_single_output(session);
    expect_contains(first, "sql: select 1");
}

void test_trace_rendering_includes_operator_steps_and_waits() {
    PgTraceSession session;
    session.set_realtime_offset_ns(0);

    const auto frontend = typed_message('Q', literal_view("select * from t\0"));
    auto frontend_event = make_read_event(303, 15, IO_DIRECTION_IN, 100'000'000ull, frontend);
    expect(session.handle_event(&frontend_event, sizeof(frontend_event)) == 0, "frontend query failed");

    auto parse_phase = make_phase_event(303, 4001, QUERY_PHASE_PARSE, 100'000'000ull, 150'000'000ull);
    auto execute_phase = make_phase_event(303, 4002, QUERY_PHASE_EXECUTE, 160'000'000ull, 260'000'000ull);
    auto seq_scan = make_operator_event(303, 4002, 2, 1, 170'000'000ull, 240'000'000ull);
    auto exec_scan = make_step_event(303, 4002, 1, 1, 180'000'000ull, 230'000'000ull);
    auto lwlock = make_wait_event(303, 4002, 2, 1, 1, 1, 190'000'000ull, 200'000'000ull);

    expect(session.handle_event(&parse_phase, sizeof(parse_phase)) == 0, "parse phase failed");
    expect(session.handle_event(&execute_phase, sizeof(execute_phase)) == 0, "execute phase failed");
    expect(session.handle_event(&seq_scan, sizeof(seq_scan)) == 0, "operator event failed");
    expect(session.handle_event(&exec_scan, sizeof(exec_scan)) == 0, "step event failed");
    expect(session.handle_event(&lwlock, sizeof(lwlock)) == 0, "wait event failed");

    const auto command_complete = typed_message('C', literal_view("SELECT 1\0"));
    auto backend_complete = make_read_event(303, 15, IO_DIRECTION_OUT, 300'000'000ull, command_complete);
    expect(session.handle_event(&backend_complete, sizeof(backend_complete)) == 0, "query completion failed");

    std::string output = take_single_output(session);
    expect_contains(output, "QUERY\n");
    expect_contains(output, "sql: select * from t");
    expect_contains(output, "`-- trace");
    expect_contains(output, "PARSE");
    expect_contains(output, "EXECUTE");
    expect_contains(output, "operators");
    expect_contains(output, "Seq Scan");
    expect_contains(output, "steps");
    expect_contains(output, "exec_scan");
    expect_contains(output, "lwlock_waits");
    expect_contains(output, "LWLockQueueSelf");
}
} // namespace

int main() {
    setenv("TZ", "UTC", 1);
    tzset();

    test_simple_query_batch_with_sql_splitting();
    test_extended_protocol_execute_uses_prepared_sql();
    test_chunked_frontend_message_reconstructs_large_sql();
    test_ready_for_query_flushes_simple_query_when_command_complete_is_missed();
    test_backend_messages_on_unconfirmed_fd_are_ignored();
    test_same_pid_can_track_multiple_socket_fds();
    test_trace_rendering_includes_operator_steps_and_waits();
    return 0;
}
