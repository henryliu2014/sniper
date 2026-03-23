#include "pg_probe.h"

#include "libbpf.h"
#include "bpf.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <deque>
#include <cctype>
#include <time.h>
#include <vector>
#include <iterator>
#include <string_view>
#include <unordered_map>
#include <string>
#include <utility>
#include <algorithm>

namespace {
volatile sig_atomic_t g_stop = 0;

enum event_type : __u32 {
    EVENT_TYPE_IO = 1,
    EVENT_TYPE_PHASE = 2,
    EVENT_TYPE_OPERATOR = 3,
};

enum query_phase : __u8 {
    QUERY_PHASE_PARSE = 1,
    QUERY_PHASE_ANALYZE = 2,
    QUERY_PHASE_PLAN = 3,
    QUERY_PHASE_EXECUTE = 4,
};

struct event_header {
    __u32 type;
};

static const char* phase_name(__u8 phase);
static const char* operator_name(__u16 op_id);

void handle_sigint(int) {
    g_stop = 1;
}

struct read_event {
    __u32 type;
    __u64 ts_ns;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __s64 count;
    __s32 len;
    __u8 direction;
    char comm[16];
    unsigned char data[4096];
};

struct phase_event {
    __u32 type;
    __u64 start_ns;
    __u64 end_ns;
    __u32 pid;
    __u32 tid;
    __u8 phase;
    char comm[16];
};

struct operator_event {
    __u32 type;
    __u64 start_ns;
    __u64 end_ns;
    __u32 pid;
    __u32 tid;
    __u16 op_id;
    char comm[16];
};

enum io_direction : __u8 {
    IO_DIRECTION_IN = 0,
    IO_DIRECTION_OUT = 1,
};

enum class request_kind {
    simple_query,
    prepare,
    execute,
};

struct query_state {
    request_kind kind;
    std::string tag;
    std::string query;
    __u64 start_ns;
    __u64 batch_id;
    struct phase_timing {
        __u8 phase;
        __u64 start_ns;
        __u64 end_ns;
        __u32 pid;
        __u32 tid;
    };
    struct operator_call {
        std::string name;
        __u64 start_ns;
        __u64 end_ns;
        __u32 tid;
    };
    std::vector<phase_timing> phases;
    std::vector<operator_call> operators;
};

struct simple_batch_state {
    __u64 batch_id;
    size_t pending_count;
};

struct connection_state {
    std::string inbound;
    std::string outbound;
    std::deque<query_state> pending_queries;
    std::deque<simple_batch_state> pending_simple_batches;
    std::unordered_map<std::string, std::string> prepared_statements;
    std::unordered_map<std::string, std::string> portals;
};

static std::unordered_map<int, connection_state> g_connections;
static std::unordered_map<__u32, int> g_pid_to_fd;
static __u64 g_realtime_offset_ns = 0;
static __u64 g_next_batch_id = 1;

enum operator_id : __u16 {
    OP_RESULT = 1,
    OP_SEQ_SCAN = 2,
    OP_INDEX_SCAN = 3,
    OP_INDEX_ONLY_SCAN = 4,
    OP_BITMAP_INDEX_SCAN = 5,
    OP_BITMAP_HEAP_SCAN = 6,
    OP_TID_SCAN = 7,
    OP_SUBQUERY_SCAN = 8,
    OP_FUNCTION_SCAN = 9,
    OP_VALUES_SCAN = 10,
    OP_CTE_SCAN = 11,
    OP_WORKTABLE_SCAN = 12,
    OP_NEST_LOOP = 13,
    OP_MERGE_JOIN = 14,
    OP_HASH_JOIN = 15,
    OP_MATERIALIZE = 16,
    OP_SORT = 17,
    OP_GROUP = 18,
    OP_AGGREGATE = 19,
    OP_WINDOW_AGG = 20,
    OP_UNIQUE = 21,
    OP_APPEND = 22,
    OP_MERGE_APPEND = 23,
    OP_LIMIT = 24,
    OP_LOCK_ROWS = 25,
    OP_MODIFY_TABLE = 26,
    OP_HASH = 27,
    OP_GATHER = 28,
    OP_GATHER_MERGE = 29,
    OP_SET_OP = 30,
    OP_PROJECT_SET = 31,
    OP_MEMOIZE = 32,
    OP_BITMAP_AND = 33,
    OP_BITMAP_OR = 34,
};

static __u32 read_be32(const unsigned char* p) {
    return (static_cast<__u32>(p[0]) << 24) |
           (static_cast<__u32>(p[1]) << 16) |
           (static_cast<__u32>(p[2]) << 8) |
           (static_cast<__u32>(p[3]));
}

static __u64 timespec_to_ns(const timespec& ts) {
    return static_cast<__u64>(ts.tv_sec) * 1000000000ull + static_cast<__u64>(ts.tv_nsec);
}

static std::string format_timestamp(__u64 mono_ns) {
    __u64 real_ns = mono_ns + g_realtime_offset_ns;
    time_t sec = static_cast<time_t>(real_ns / 1000000000ull);
    long millis = static_cast<long>((real_ns % 1000000000ull) / 1000000ull);
    struct tm tm_buf;
    localtime_r(&sec, &tm_buf);

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    char out[80];
    snprintf(out, sizeof(out), "%s.%03ld", buf, millis);
    return out;
}

static double duration_ms(__u64 start_ns, __u64 end_ns) {
    return static_cast<double>(end_ns - start_ns) / 1000000.0;
}

static void print_tree_leaf(const char* prefix, bool last, const char* key, const std::string& value) {
    fprintf(stdout, "%s%s%s: %s\n", prefix, last ? "`-- " : "|-- ", key, value.c_str());
}

static void print_tree_leaf(const char* prefix, bool last, const char* key, double value) {
    fprintf(stdout, "%s%s%s: %.3f\n", prefix, last ? "`-- " : "|-- ", key, value);
}

static void print_tree_leaf(const char* prefix, bool last, const char* key, unsigned value) {
    fprintf(stdout, "%s%s%s: %u\n", prefix, last ? "`-- " : "|-- ", key, value);
}

static void print_operator_calls(const query_state& query, const char* prefix, bool last_section) {
    if (query.operators.empty()) {
        return;
    }

    fprintf(stdout, "%s%soperators\n", prefix, last_section ? "`-- " : "|-- ");
    const std::string operator_prefix = std::string(prefix) + (last_section ? "    " : "|   ");
    std::vector<const query_state::operator_call*> ordered_ops;
    ordered_ops.reserve(query.operators.size());
    for (const auto& op : query.operators) {
        ordered_ops.push_back(&op);
    }
    std::sort(ordered_ops.begin(), ordered_ops.end(),
              [](const query_state::operator_call* lhs, const query_state::operator_call* rhs) {
                  if (lhs->start_ns != rhs->start_ns) {
                      return lhs->start_ns < rhs->start_ns;
                  }
                  if (lhs->end_ns != rhs->end_ns) {
                      return lhs->end_ns < rhs->end_ns;
                  }
                  if (lhs->tid != rhs->tid) {
                      return lhs->tid < rhs->tid;
                  }
                  return lhs->name < rhs->name;
              });

    for (size_t i = 0; i < ordered_ops.size(); ++i) {
        const auto& op = *ordered_ops[i];
        bool op_last = i + 1 == query.operators.size();
        const char* child_prefix = op_last ? "    " : "|   ";
        fprintf(stdout, "%s%s%s\n", operator_prefix.c_str(), op_last ? "`-- " : "|-- ", op.name.c_str());
        std::string details_prefix = operator_prefix + child_prefix;
        print_tree_leaf(details_prefix.c_str(), false, "start_time", format_timestamp(op.start_ns));
        print_tree_leaf(details_prefix.c_str(), false, "end_time", format_timestamp(op.end_ns));
        print_tree_leaf(details_prefix.c_str(), false, "duration_ms", duration_ms(op.start_ns, op.end_ns));
        print_tree_leaf(details_prefix.c_str(), true, "tid", op.tid);
    }
}

static void print_query_timing(const query_state& query, __u64 finish_ns) {
    fprintf(stdout, "%s\n", query.tag.c_str());
    print_tree_leaf("", false, "sql", query.query);
    print_tree_leaf("", false, "start_time", format_timestamp(query.start_ns));
    print_tree_leaf("", false, "end_time", format_timestamp(finish_ns));

    if (query.phases.empty()) {
        print_tree_leaf("", true, "duration_ms", duration_ms(query.start_ns, finish_ns));
        return;
    }

    print_tree_leaf("", false, "duration_ms", duration_ms(query.start_ns, finish_ns));
    fprintf(stdout, "`-- trace\n");
    constexpr const char* trace_prefix = "    ";
    for (size_t i = 0; i < query.phases.size(); ++i) {
        const auto& phase = query.phases[i];
        bool phase_last = (i + 1 == query.phases.size());
        const char* branch = phase_last ? "`-- " : "|-- ";
        const char* child_prefix = phase_last ? "        " : "    |   ";
        bool is_execute_phase = phase.phase == QUERY_PHASE_EXECUTE;
        bool print_operators = is_execute_phase && !query.operators.empty();

        fprintf(stdout, "%s%s%s\n", trace_prefix, branch, phase_name(phase.phase));
        print_tree_leaf(child_prefix, false, "start_time", format_timestamp(phase.start_ns));
        print_tree_leaf(child_prefix, false, "end_time", format_timestamp(phase.end_ns));
        print_tree_leaf(child_prefix, false, "duration_ms", duration_ms(phase.start_ns, phase.end_ns));
        print_tree_leaf(child_prefix, false, "pid", phase.pid);
        print_tree_leaf(child_prefix, print_operators ? false : true, "tid", phase.tid);
        if (print_operators) {
            print_operator_calls(query, child_prefix, true);
        }
    }
}

static const char* phase_name(__u8 phase) {
    switch (phase) {
    case QUERY_PHASE_PARSE:
        return "PARSE";
    case QUERY_PHASE_ANALYZE:
        return "ANALYZE";
    case QUERY_PHASE_PLAN:
        return "PLAN";
    case QUERY_PHASE_EXECUTE:
        return "EXECUTE";
    default:
        return "UNKNOWN";
    }
}

static const char* operator_name(__u16 op_id) {
    switch (op_id) {
    case OP_RESULT:
        return "Result";
    case OP_SEQ_SCAN:
        return "Seq Scan";
    case OP_INDEX_SCAN:
        return "Index Scan";
    case OP_INDEX_ONLY_SCAN:
        return "Index Only Scan";
    case OP_BITMAP_INDEX_SCAN:
        return "Bitmap Index Scan";
    case OP_BITMAP_HEAP_SCAN:
        return "Bitmap Heap Scan";
    case OP_TID_SCAN:
        return "Tid Scan";
    case OP_SUBQUERY_SCAN:
        return "Subquery Scan";
    case OP_FUNCTION_SCAN:
        return "Function Scan";
    case OP_VALUES_SCAN:
        return "Values Scan";
    case OP_CTE_SCAN:
        return "CTE Scan";
    case OP_WORKTABLE_SCAN:
        return "WorkTable Scan";
    case OP_NEST_LOOP:
        return "Nested Loop";
    case OP_MERGE_JOIN:
        return "Merge Join";
    case OP_HASH_JOIN:
        return "Hash Join";
    case OP_MATERIALIZE:
        return "Materialize";
    case OP_SORT:
        return "Sort";
    case OP_GROUP:
        return "Group";
    case OP_AGGREGATE:
        return "Aggregate";
    case OP_WINDOW_AGG:
        return "WindowAgg";
    case OP_UNIQUE:
        return "Unique";
    case OP_APPEND:
        return "Append";
    case OP_MERGE_APPEND:
        return "Merge Append";
    case OP_LIMIT:
        return "Limit";
    case OP_LOCK_ROWS:
        return "LockRows";
    case OP_MODIFY_TABLE:
        return "ModifyTable";
    case OP_HASH:
        return "Hash";
    case OP_GATHER:
        return "Gather";
    case OP_GATHER_MERGE:
        return "Gather Merge";
    case OP_SET_OP:
        return "SetOp";
    case OP_PROJECT_SET:
        return "ProjectSet";
    case OP_MEMOIZE:
        return "Memoize";
    case OP_BITMAP_AND:
        return "BitmapAnd";
    case OP_BITMAP_OR:
        return "BitmapOr";
    default:
        return "Unknown Operator";
    }
}

static query_state* current_query_for_pid(__u32 pid) {
    auto fd_it = g_pid_to_fd.find(pid);
    if (fd_it == g_pid_to_fd.end()) {
        return nullptr;
    }

    auto conn_it = g_connections.find(fd_it->second);
    if (conn_it == g_connections.end() || conn_it->second.pending_queries.empty()) {
        return nullptr;
    }

    query_state& query = conn_it->second.pending_queries.front();
    return &query;
}

static void print_phase_timing(const phase_event& event) {
    query_state* query = current_query_for_pid(event.pid);
    if (!query) {
        return;
    }

    query->phases.push_back(query_state::phase_timing{
        .phase = event.phase,
        .start_ns = event.start_ns,
        .end_ns = event.end_ns,
        .pid = event.pid,
        .tid = event.tid,
    });
}

static void record_operator(const operator_event& event) {
    query_state* query = current_query_for_pid(event.pid);
    if (!query) {
        return;
    }

    if (event.end_ns < event.start_ns) {
        return;
    }

    query->operators.push_back(query_state::operator_call{
        .name = operator_name(event.op_id),
        .start_ns = event.start_ns,
        .end_ns = event.end_ns,
        .tid = event.tid,
    });
}

static std::string_view trim_sql(std::string_view sql) {
    size_t begin = 0;
    size_t end = sql.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(sql[begin]))) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(sql[end - 1]))) {
        --end;
    }
    return sql.substr(begin, end - begin);
}

static bool is_ident_char(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

static std::vector<std::string> split_simple_query(std::string_view sql) {
    std::vector<std::string> statements;
    size_t start = 0;
    bool in_single_quote = false;
    bool in_double_quote = false;
    bool in_line_comment = false;
    bool in_block_comment = false;
    std::string dollar_tag;

    for (size_t i = 0; i < sql.size(); ++i) {
        char c = sql[i];
        char next = (i + 1 < sql.size()) ? sql[i + 1] : '\0';

        if (!dollar_tag.empty()) {
            if (c == '$' && i + dollar_tag.size() <= sql.size() &&
                sql.compare(i, dollar_tag.size(), dollar_tag) == 0) {
                i += dollar_tag.size() - 1;
                dollar_tag.clear();
            }
            continue;
        }

        if (in_line_comment) {
            if (c == '\n') {
                in_line_comment = false;
            }
            continue;
        }

        if (in_block_comment) {
            if (c == '*' && next == '/') {
                in_block_comment = false;
                ++i;
            }
            continue;
        }

        if (in_single_quote) {
            if (c == '\'') {
                if (next == '\'') {
                    ++i;
                } else {
                    in_single_quote = false;
                }
            }
            continue;
        }

        if (in_double_quote) {
            if (c == '"') {
                if (next == '"') {
                    ++i;
                } else {
                    in_double_quote = false;
                }
            }
            continue;
        }

        if (c == '-' && next == '-') {
            in_line_comment = true;
            ++i;
            continue;
        }

        if (c == '/' && next == '*') {
            in_block_comment = true;
            ++i;
            continue;
        }

        if (c == '\'') {
            in_single_quote = true;
            continue;
        }

        if (c == '"') {
            in_double_quote = true;
            continue;
        }

        if (c == '$') {
            size_t j = i + 1;
            while (j < sql.size() && sql[j] != '$' && is_ident_char(sql[j])) {
                ++j;
            }
            if (j < sql.size() && sql[j] == '$') {
                dollar_tag = std::string(sql.substr(i, j - i + 1));
                i = j;
                continue;
            }
        }

        if (c == ';') {
            std::string_view stmt = trim_sql(sql.substr(start, i - start));
            if (!stmt.empty()) {
                statements.emplace_back(stmt);
            }
            start = i + 1;
        }
    }

    std::string_view stmt = trim_sql(sql.substr(start));
    if (!stmt.empty()) {
        statements.emplace_back(stmt);
    }

    return statements;
}

static void queue_query(int fd, request_kind kind, const char* tag, const char* query, size_t len,
                        __u64 ts_ns, __u64 batch_id = 0) {
    if (len == 0) {
        return;
    }
    auto& conn = g_connections[fd];
    conn.pending_queries.push_back(query_state{
        .kind = kind,
        .tag = tag,
        .query = std::string(query, len),
        .start_ns = ts_ns,
        .batch_id = batch_id,
    });
}

static void finish_query(int fd, request_kind kind, __u64 ts_ns) {
    auto it = g_connections.find(fd);
    if (it == g_connections.end()) {
        return;
    }

    auto& pending = it->second.pending_queries;
    if (pending.empty() || pending.front().kind != kind) {
        return;
    }

    query_state query = std::move(pending.front());
    pending.pop_front();
    print_query_timing(query, ts_ns);

    if (kind == request_kind::simple_query) {
        auto& batches = it->second.pending_simple_batches;
        if (!batches.empty() && batches.front().batch_id == query.batch_id && batches.front().pending_count > 0) {
            --batches.front().pending_count;
        }
    }
}

static void finish_front_query(int fd, __u64 ts_ns) {
    auto it = g_connections.find(fd);
    if (it == g_connections.end() || it->second.pending_queries.empty()) {
        return;
    }
    finish_query(fd, it->second.pending_queries.front().kind, ts_ns);
}

static void queue_simple_query_batch(int fd, std::string_view sql, __u64 ts_ns) {
    std::vector<std::string> statements = split_simple_query(sql);
    if (statements.empty()) {
        return;
    }

    auto& conn = g_connections[fd];
    __u64 batch_id = g_next_batch_id++;
    conn.pending_simple_batches.push_back(simple_batch_state{
        .batch_id = batch_id,
        .pending_count = statements.size(),
    });

    for (const std::string& statement : statements) {
        queue_query(fd, request_kind::simple_query, "QUERY",
                    statement.data(), statement.size(), ts_ns, batch_id);
    }
}

static void finish_simple_query_batch(int fd, __u64 ts_ns) {
    auto it = g_connections.find(fd);
    if (it == g_connections.end()) {
        return;
    }

    auto& conn = it->second;
    if (conn.pending_simple_batches.empty()) {
        return;
    }

    simple_batch_state batch = conn.pending_simple_batches.front();
    conn.pending_simple_batches.pop_front();
    while (batch.pending_count > 0 && !conn.pending_queries.empty()) {
        const query_state& query = conn.pending_queries.front();
        if (query.kind != request_kind::simple_query || query.batch_id != batch.batch_id) {
            break;
        }
        conn.pending_queries.pop_front();
        --batch.pending_count;
    }
}

static void parse_frontend_messages(int fd, const unsigned char* data, size_t len, __u64 ts_ns) {
    if (len == 0) {
        return;
    }

    auto& buf = g_connections[fd].inbound;
    buf.append(reinterpret_cast<const char*>(data), len);

    const size_t kMaxBuffer = 1u << 20;
    if (buf.size() > kMaxBuffer) {
        buf.clear();
        return;
    }

    while (true) {
        if (buf.size() < 4) {
            return;
        }

        unsigned char first = static_cast<unsigned char>(buf[0]);
        bool typed = (first >= 'A' && first <= 'Z');
        size_t header = typed ? 5 : 4;
        if (buf.size() < header) {
            return;
        }

        const unsigned char* p = reinterpret_cast<const unsigned char*>(buf.data());
        __u32 msg_len = typed ? read_be32(p + 1) : read_be32(p);
        if (msg_len < 4) {
            buf.clear();
            return;
        }

        size_t total = typed ? (1 + msg_len) : msg_len;
        if (buf.size() < total) {
            return;
        }

        if (typed && (first == 'Q' || first == 'P')) {
            const char* payload = reinterpret_cast<const char*>(p + 5);
            size_t payload_len = msg_len - 4;
            if (first == 'Q') {
                const char* end = static_cast<const char*>(
                    memchr(payload, '\0', payload_len));
                size_t qlen = end ? static_cast<size_t>(end - payload) : payload_len;
                queue_simple_query_batch(fd, std::string_view(payload, qlen), ts_ns);
            } else if (first == 'P') {
                const char* name_end = static_cast<const char*>(
                    memchr(payload, '\0', payload_len));
                if (name_end) {
                    auto& conn = g_connections[fd];
                    size_t remaining = payload_len - static_cast<size_t>(name_end - payload) - 1;
                    const char* query = name_end + 1;
                    const char* q_end = static_cast<const char*>(
                        memchr(query, '\0', remaining));
                    size_t qlen = q_end ? static_cast<size_t>(q_end - query) : remaining;
                    std::string stmt_name(payload, static_cast<size_t>(name_end - payload));
                    conn.prepared_statements[stmt_name] = std::string(query, qlen);
                    queue_query(fd, request_kind::prepare, "PREPARE", query, qlen, ts_ns);
                }
            }
        } else if (typed && first == 'B') {
            const char* payload = reinterpret_cast<const char*>(p + 5);
            size_t payload_len = msg_len - 4;
            const char* portal_end = static_cast<const char*>(memchr(payload, '\0', payload_len));
            if (portal_end) {
                size_t remaining = payload_len - static_cast<size_t>(portal_end - payload) - 1;
                const char* statement = portal_end + 1;
                const char* statement_end = static_cast<const char*>(memchr(statement, '\0', remaining));
                if (statement_end) {
                    auto& conn = g_connections[fd];
                    conn.portals[std::string(payload, static_cast<size_t>(portal_end - payload))] =
                        std::string(statement, static_cast<size_t>(statement_end - statement));
                }
            }
        } else if (typed && first == 'E') {
            const char* payload = reinterpret_cast<const char*>(p + 5);
            size_t payload_len = msg_len - 4;
            const char* portal_end = static_cast<const char*>(memchr(payload, '\0', payload_len));
            if (portal_end) {
                auto& conn = g_connections[fd];
                std::string portal(payload, static_cast<size_t>(portal_end - payload));
                auto portal_it = conn.portals.find(portal);
                if (portal_it != conn.portals.end()) {
                    auto stmt_it = conn.prepared_statements.find(portal_it->second);
                    if (stmt_it != conn.prepared_statements.end()) {
                        queue_query(fd, request_kind::execute, "EXECUTE",
                                    stmt_it->second.data(), stmt_it->second.size(), ts_ns);
                    }
                }
            }
        }

        buf.erase(0, total);
    }
}

static void parse_backend_messages(int fd, const unsigned char* data, size_t len, __u64 ts_ns) {
    if (len == 0) {
        return;
    }

    auto& buf = g_connections[fd].outbound;
    buf.append(reinterpret_cast<const char*>(data), len);

    const size_t kMaxBuffer = 1u << 20;
    if (buf.size() > kMaxBuffer) {
        buf.clear();
        return;
    }

    while (true) {
        if (buf.size() < 5) {
            return;
        }

        const unsigned char* p = reinterpret_cast<const unsigned char*>(buf.data());
        __u32 msg_len = read_be32(p + 1);
        if (msg_len < 4) {
            buf.clear();
            return;
        }

        size_t total = 1 + msg_len;
        if (buf.size() < total) {
            return;
        }

        unsigned char tag = p[0];
        if (tag == 'C' || tag == 'E' || tag == 'I') {
            finish_front_query(fd, ts_ns);
        } else if (tag == '1') {
            finish_query(fd, request_kind::prepare, ts_ns);
        } else if (tag == 's') {
            finish_query(fd, request_kind::execute, ts_ns);
        } else if (tag == 'Z') {
            finish_simple_query_batch(fd, ts_ns);
        }

        buf.erase(0, total);
    }
}

int handle_event(void* /*ctx*/, void* data, size_t /*data_sz*/) {
    const auto* header = static_cast<const event_header*>(data);
    if (header->type == EVENT_TYPE_IO) {
        const auto* e = static_cast<const read_event*>(data);
        g_pid_to_fd[e->pid] = e->fd;
        if (e->len > 0) {
            if (e->direction == IO_DIRECTION_IN) {
                parse_frontend_messages(e->fd, e->data, static_cast<size_t>(e->len), e->ts_ns);
            } else if (e->direction == IO_DIRECTION_OUT) {
                parse_backend_messages(e->fd, e->data, static_cast<size_t>(e->len), e->ts_ns);
            }
        }
    } else if (header->type == EVENT_TYPE_PHASE) {
        const auto* e = static_cast<const phase_event*>(data);
        print_phase_timing(*e);
    } else if (header->type == EVENT_TYPE_OPERATOR) {
        const auto* e = static_cast<const operator_event*>(data);
        record_operator(*e);
    } else {
        printf("no header type");
    }
    return 0;
}

static std::string read_proc_exe(pid_t pid) {
    char link_path[64];
    snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);

    char exe_path[PATH_MAX];
    ssize_t len = readlink(link_path, exe_path, sizeof(exe_path) - 1);
    if (len < 0) {
        return {};
    }

    exe_path[len] = '\0';
    return exe_path;
}

static bpf_link* attach_named_uprobe(struct bpf_program* prog, const char* binary_path,
                                     const char* func_name, bool retprobe) {
    LIBBPF_OPTS(bpf_uprobe_opts, opts,
        .retprobe = retprobe,
        .func_name = func_name);
    return bpf_program__attach_uprobe_opts(prog, -1, binary_path, 0, &opts);
}

static bool link_is_ok(struct bpf_link* link) {
    return link != nullptr && libbpf_get_error(link) == 0;
}
} // namespace

int pg_probe(const std::vector<pid_t>& postgres_pids, int duration_sec) {
    if (postgres_pids.empty()) {
        fprintf(stderr, "pg_probe: no postgres pids provided\n");
        return -1;
    }

    if (duration_sec <= 0) {
        duration_sec = 10;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print([](enum libbpf_print_level level, const char* fmt, va_list args) -> int {
        if (level == LIBBPF_DEBUG) {
            return 0;
        }
        return vfprintf(stderr, fmt, args);
    });

    struct bpf_object* obj = nullptr;
    struct bpf_program* prog_enter_recvfrom = nullptr;
    struct bpf_program* prog_exit_recvfrom = nullptr;
    struct bpf_program* prog_enter_write = nullptr;
    struct bpf_program* prog_exit_write = nullptr;
    struct bpf_program* prog_enter_sendto = nullptr;
    struct bpf_program* prog_exit_sendto = nullptr;
    struct bpf_program* prog_parse_enter = nullptr;
    struct bpf_program* prog_parse_exit = nullptr;
    struct bpf_program* prog_analyze_fixed_enter = nullptr;
    struct bpf_program* prog_analyze_fixed_exit = nullptr;
    struct bpf_program* prog_analyze_var_enter = nullptr;
    struct bpf_program* prog_analyze_var_exit = nullptr;
    struct bpf_program* prog_analyze_cb_enter = nullptr;
    struct bpf_program* prog_analyze_cb_exit = nullptr;
    struct bpf_program* prog_plan_enter = nullptr;
    struct bpf_program* prog_plan_exit = nullptr;
    struct bpf_program* prog_portal_run_enter = nullptr;
    struct bpf_program* prog_portal_run_exit = nullptr;
    struct operator_probe_spec {
        const char* enter_prog_name;
        const char* exit_prog_name;
        const char* func_name;
    };
    static constexpr operator_probe_spec operator_specs[] = {
        {"trace_ExecResult_enter", "trace_ExecResult_exit", "ExecResult"},
        {"trace_ExecSeqScan_enter", "trace_ExecSeqScan_exit", "ExecSeqScan"},
        {"trace_ExecIndexScan_enter", "trace_ExecIndexScan_exit", "ExecIndexScan"},
        {"trace_ExecIndexOnlyScan_enter", "trace_ExecIndexOnlyScan_exit", "ExecIndexOnlyScan"},
        {"trace_ExecBitmapIndexScan_enter", "trace_ExecBitmapIndexScan_exit", "ExecBitmapIndexScan"},
        {"trace_ExecBitmapHeapScan_enter", "trace_ExecBitmapHeapScan_exit", "ExecBitmapHeapScan"},
        {"trace_ExecTidScan_enter", "trace_ExecTidScan_exit", "ExecTidScan"},
        {"trace_ExecSubqueryScan_enter", "trace_ExecSubqueryScan_exit", "ExecSubqueryScan"},
        {"trace_ExecFunctionScan_enter", "trace_ExecFunctionScan_exit", "ExecFunctionScan"},
        {"trace_ExecValuesScan_enter", "trace_ExecValuesScan_exit", "ExecValuesScan"},
        {"trace_ExecCteScan_enter", "trace_ExecCteScan_exit", "ExecCteScan"},
        {"trace_ExecWorkTableScan_enter", "trace_ExecWorkTableScan_exit", "ExecWorkTableScan"},
        {"trace_ExecNestLoop_enter", "trace_ExecNestLoop_exit", "ExecNestLoop"},
        {"trace_ExecMergeJoin_enter", "trace_ExecMergeJoin_exit", "ExecMergeJoin"},
        {"trace_ExecHashJoin_enter", "trace_ExecHashJoin_exit", "ExecHashJoin"},
        {"trace_ExecMaterial_enter", "trace_ExecMaterial_exit", "ExecMaterial"},
        {"trace_ExecSort_enter", "trace_ExecSort_exit", "ExecSort"},
        {"trace_ExecGroup_enter", "trace_ExecGroup_exit", "ExecGroup"},
        {"trace_ExecAgg_enter", "trace_ExecAgg_exit", "ExecAgg"},
        {"trace_ExecWindowAgg_enter", "trace_ExecWindowAgg_exit", "ExecWindowAgg"},
        {"trace_ExecUnique_enter", "trace_ExecUnique_exit", "ExecUnique"},
        {"trace_ExecAppend_enter", "trace_ExecAppend_exit", "ExecAppend"},
        {"trace_ExecMergeAppend_enter", "trace_ExecMergeAppend_exit", "ExecMergeAppend"},
        {"trace_ExecLimit_enter", "trace_ExecLimit_exit", "ExecLimit"},
        {"trace_ExecLockRows_enter", "trace_ExecLockRows_exit", "ExecLockRows"},
        {"trace_ExecModifyTable_enter", "trace_ExecModifyTable_exit", "ExecModifyTable"},
        {"trace_ExecHash_enter", "trace_ExecHash_exit", "ExecHash"},
        {"trace_ExecGather_enter", "trace_ExecGather_exit", "ExecGather"},
        {"trace_ExecGatherMerge_enter", "trace_ExecGatherMerge_exit", "ExecGatherMerge"},
        {"trace_ExecSetOp_enter", "trace_ExecSetOp_exit", "ExecSetOp"},
        {"trace_ExecProjectSet_enter", "trace_ExecProjectSet_exit", "ExecProjectSet"},
        {"trace_ExecMemoize_enter", "trace_ExecMemoize_exit", "ExecMemoize"},
        {"trace_MultiExecBitmapAnd_enter", "trace_MultiExecBitmapAnd_exit", "MultiExecBitmapAnd"},
        {"trace_MultiExecBitmapOr_enter", "trace_MultiExecBitmapOr_exit", "MultiExecBitmapOr"},
    };
    std::vector<struct bpf_program*> prog_operator_enters;
    std::vector<struct bpf_program*> prog_operator_exits;
    struct bpf_link* link_enter_recvfrom = nullptr;
    struct bpf_link* link_exit_recvfrom = nullptr;
    struct bpf_link* link_enter_write = nullptr;
    struct bpf_link* link_exit_write = nullptr;
    struct bpf_link* link_enter_sendto = nullptr;
    struct bpf_link* link_exit_sendto = nullptr;
    struct bpf_link* link_parse_enter = nullptr;
    struct bpf_link* link_parse_exit = nullptr;
    struct bpf_link* link_analyze_fixed_enter = nullptr;
    struct bpf_link* link_analyze_fixed_exit = nullptr;
    struct bpf_link* link_analyze_var_enter = nullptr;
    struct bpf_link* link_analyze_var_exit = nullptr;
    struct bpf_link* link_analyze_cb_enter = nullptr;
    struct bpf_link* link_analyze_cb_exit = nullptr;
    struct bpf_link* link_plan_enter = nullptr;
    struct bpf_link* link_plan_exit = nullptr;
    struct bpf_link* link_portal_run_enter = nullptr;
    struct bpf_link* link_portal_run_exit = nullptr;
    std::vector<struct bpf_link*> link_operator_enters;
    std::vector<struct bpf_link*> link_operator_exits;
    struct ring_buffer* rb = nullptr;
    std::string postgres_binary;
    auto destroy_links = [&]() {
        bpf_link__destroy(link_portal_run_exit);
        bpf_link__destroy(link_portal_run_enter);
        bpf_link__destroy(link_plan_exit);
        bpf_link__destroy(link_plan_enter);
        bpf_link__destroy(link_analyze_cb_exit);
        bpf_link__destroy(link_analyze_cb_enter);
        bpf_link__destroy(link_analyze_var_exit);
        bpf_link__destroy(link_analyze_var_enter);
        bpf_link__destroy(link_analyze_fixed_exit);
        bpf_link__destroy(link_analyze_fixed_enter);
        bpf_link__destroy(link_parse_exit);
        bpf_link__destroy(link_parse_enter);
        for (struct bpf_link* link : link_operator_enters) {
            bpf_link__destroy(link);
        }
        for (struct bpf_link* link : link_operator_exits) {
            bpf_link__destroy(link);
        }
        bpf_link__destroy(link_exit_sendto);
        bpf_link__destroy(link_enter_sendto);
        bpf_link__destroy(link_exit_write);
        bpf_link__destroy(link_enter_write);
        bpf_link__destroy(link_exit_recvfrom);
        bpf_link__destroy(link_enter_recvfrom);
    };

    timespec realtime_ts {};
    timespec monotonic_ts {};
    if (clock_gettime(CLOCK_REALTIME, &realtime_ts) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic_ts) != 0) {
        fprintf(stderr, "pg_probe: failed to read clocks\n");
        return -1;
    }
    g_realtime_offset_ns = timespec_to_ns(realtime_ts) - timespec_to_ns(monotonic_ts);
    postgres_binary = read_proc_exe(postgres_pids.front());
    if (postgres_binary.empty()) {
        fprintf(stderr, "pg_probe: failed to resolve postgres binary path\n");
        return -1;
    }

    obj = bpf_object__open_file("pg_probe.bpf.o", nullptr);
    if (!obj) {
        fprintf(stderr, "pg_probe: failed to open BPF object\n");
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "pg_probe: failed to load BPF object\n");
        bpf_object__close(obj);
        return -1;
    }

    prog_enter_recvfrom = bpf_object__find_program_by_name(obj, "trace_sys_enter_recvfrom");
    prog_exit_recvfrom = bpf_object__find_program_by_name(obj, "trace_sys_exit_recvfrom");
    prog_enter_write = bpf_object__find_program_by_name(obj, "trace_sys_enter_write");
    prog_exit_write = bpf_object__find_program_by_name(obj, "trace_sys_exit_write");
    prog_enter_sendto = bpf_object__find_program_by_name(obj, "trace_sys_enter_sendto");
    prog_exit_sendto = bpf_object__find_program_by_name(obj, "trace_sys_exit_sendto");
    prog_parse_enter = bpf_object__find_program_by_name(obj, "trace_pg_parse_query_enter");
    prog_parse_exit = bpf_object__find_program_by_name(obj, "trace_pg_parse_query_exit");
    prog_analyze_fixed_enter = bpf_object__find_program_by_name(obj, "trace_pg_analyze_and_rewrite_fixedparams_enter");
    prog_analyze_fixed_exit = bpf_object__find_program_by_name(obj, "trace_pg_analyze_and_rewrite_fixedparams_exit");
    prog_analyze_var_enter = bpf_object__find_program_by_name(obj, "trace_pg_analyze_and_rewrite_varparams_enter");
    prog_analyze_var_exit = bpf_object__find_program_by_name(obj, "trace_pg_analyze_and_rewrite_varparams_exit");
    prog_analyze_cb_enter = bpf_object__find_program_by_name(obj, "trace_pg_analyze_and_rewrite_withcb_enter");
    prog_analyze_cb_exit = bpf_object__find_program_by_name(obj, "trace_pg_analyze_and_rewrite_withcb_exit");
    prog_plan_enter = bpf_object__find_program_by_name(obj, "trace_pg_plan_queries_enter");
    prog_plan_exit = bpf_object__find_program_by_name(obj, "trace_pg_plan_queries_exit");
    prog_portal_run_enter = bpf_object__find_program_by_name(obj, "trace_PortalRun_enter");
    prog_portal_run_exit = bpf_object__find_program_by_name(obj, "trace_PortalRun_exit");
    prog_operator_enters.reserve(std::size(operator_specs));
    prog_operator_exits.reserve(std::size(operator_specs));
    for (const auto& spec : operator_specs) {
        prog_operator_enters.push_back(bpf_object__find_program_by_name(obj, spec.enter_prog_name));
        prog_operator_exits.push_back(bpf_object__find_program_by_name(obj, spec.exit_prog_name));
    }
    if (!prog_enter_recvfrom || !prog_exit_recvfrom ||
        !prog_enter_write || !prog_exit_write || !prog_enter_sendto || !prog_exit_sendto ||
        !prog_parse_enter || !prog_parse_exit ||
        !prog_analyze_fixed_enter || !prog_analyze_fixed_exit ||
        !prog_analyze_var_enter || !prog_analyze_var_exit ||
        !prog_analyze_cb_enter || !prog_analyze_cb_exit ||
        !prog_plan_enter || !prog_plan_exit ||
        !prog_portal_run_enter || !prog_portal_run_exit) {
        fprintf(stderr, "pg_probe: program not found\n");
        bpf_object__close(obj);
        return -1;
    }

    link_enter_recvfrom = bpf_program__attach_tracepoint(prog_enter_recvfrom, "syscalls", "sys_enter_recvfrom");
    link_exit_recvfrom = bpf_program__attach_tracepoint(prog_exit_recvfrom, "syscalls", "sys_exit_recvfrom");
    link_enter_write = bpf_program__attach_tracepoint(prog_enter_write, "syscalls", "sys_enter_write");
    link_exit_write = bpf_program__attach_tracepoint(prog_exit_write, "syscalls", "sys_exit_write");
    link_enter_sendto = bpf_program__attach_tracepoint(prog_enter_sendto, "syscalls", "sys_enter_sendto");
    link_exit_sendto = bpf_program__attach_tracepoint(prog_exit_sendto, "syscalls", "sys_exit_sendto");
    link_parse_enter = attach_named_uprobe(prog_parse_enter, postgres_binary.c_str(), "pg_parse_query", false);
    link_parse_exit = attach_named_uprobe(prog_parse_exit, postgres_binary.c_str(), "pg_parse_query", true);
    link_analyze_fixed_enter = attach_named_uprobe(prog_analyze_fixed_enter, postgres_binary.c_str(),
                                                   "pg_analyze_and_rewrite_fixedparams", false);
    link_analyze_fixed_exit = attach_named_uprobe(prog_analyze_fixed_exit, postgres_binary.c_str(),
                                                  "pg_analyze_and_rewrite_fixedparams", true);
    link_analyze_var_enter = attach_named_uprobe(prog_analyze_var_enter, postgres_binary.c_str(),
                                                 "pg_analyze_and_rewrite_varparams", false);
    link_analyze_var_exit = attach_named_uprobe(prog_analyze_var_exit, postgres_binary.c_str(),
                                                "pg_analyze_and_rewrite_varparams", true);
    link_analyze_cb_enter = attach_named_uprobe(prog_analyze_cb_enter, postgres_binary.c_str(),
                                                "pg_analyze_and_rewrite_withcb", false);
    link_analyze_cb_exit = attach_named_uprobe(prog_analyze_cb_exit, postgres_binary.c_str(),
                                               "pg_analyze_and_rewrite_withcb", true);
    link_plan_enter = attach_named_uprobe(prog_plan_enter, postgres_binary.c_str(), "pg_plan_queries", false);
    link_plan_exit = attach_named_uprobe(prog_plan_exit, postgres_binary.c_str(), "pg_plan_queries", true);
    link_portal_run_enter = attach_named_uprobe(prog_portal_run_enter, postgres_binary.c_str(), "PortalRun", false);
    link_portal_run_exit = attach_named_uprobe(prog_portal_run_exit, postgres_binary.c_str(), "PortalRun", true);
    link_operator_enters.reserve(std::size(operator_specs));
    link_operator_exits.reserve(std::size(operator_specs));
    for (size_t i = 0; i < std::size(operator_specs); ++i) {
        struct bpf_link* enter_link = nullptr;
        struct bpf_link* exit_link = nullptr;
        if (prog_operator_enters[i]) {
            enter_link = attach_named_uprobe(prog_operator_enters[i], postgres_binary.c_str(), operator_specs[i].func_name, false);
            if (!link_is_ok(enter_link)) {
                enter_link = nullptr;
            }
        }
        if (prog_operator_exits[i]) {
            exit_link = attach_named_uprobe(prog_operator_exits[i], postgres_binary.c_str(), operator_specs[i].func_name, true);
            if (!link_is_ok(exit_link)) {
                exit_link = nullptr;
            }
        }
        link_operator_enters.push_back(enter_link);
        link_operator_exits.push_back(exit_link);
    }
    if (!link_is_ok(link_enter_recvfrom) || !link_is_ok(link_exit_recvfrom) ||
        !link_is_ok(link_enter_write) || !link_is_ok(link_exit_write) ||
        !link_is_ok(link_enter_sendto) || !link_is_ok(link_exit_sendto) ||
        !link_is_ok(link_parse_enter) || !link_is_ok(link_parse_exit) ||
        !link_is_ok(link_analyze_fixed_enter) || !link_is_ok(link_analyze_fixed_exit) ||
        !link_is_ok(link_analyze_var_enter) || !link_is_ok(link_analyze_var_exit) ||
        !link_is_ok(link_analyze_cb_enter) || !link_is_ok(link_analyze_cb_exit) ||
        !link_is_ok(link_plan_enter) || !link_is_ok(link_plan_exit) ||
        !link_is_ok(link_portal_run_enter) || !link_is_ok(link_portal_run_exit)) {
        fprintf(stderr, "pg_probe: attach failed\n");
        destroy_links();
        bpf_object__close(obj);
        return -1;
    }

    int pid_map_fd = bpf_object__find_map_fd_by_name(obj, "target_pids");
    if (pid_map_fd < 0) {
        fprintf(stderr, "pg_probe: target_pids map not found\n");
        destroy_links();
        bpf_object__close(obj);
        return -1;
    }

    for (pid_t p : postgres_pids) {
        if (p <= 0) {
            continue;
        }
        __u32 pid = static_cast<__u32>(p);
        __u8 enabled = 1;
        if (bpf_map_update_elem(pid_map_fd, &pid, &enabled, BPF_ANY) != 0) {
            fprintf(stderr, "pg_probe: failed to set target pid %u: %s\n",
                    pid, strerror(errno));
            destroy_links();
            bpf_object__close(obj);
            return -1;
        }
    }

    int rb_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (rb_fd < 0) {
        fprintf(stderr, "pg_probe: events map not found\n");
        destroy_links();
        bpf_object__close(obj);
        return -1;
    }

    rb = ring_buffer__new(rb_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        fprintf(stderr, "pg_probe: ring buffer setup failed\n");
        destroy_links();
        bpf_object__close(obj);
        return -1;
    }

    signal(SIGINT, handle_sigint);

    const int timeout_ms = 200;
    const int max_iters = (duration_sec * 1000) / timeout_ms;
    for (int i = 0; i < max_iters && !g_stop; ++i) {
        int err = ring_buffer__poll(rb, timeout_ms);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "pg_probe: ring buffer poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    destroy_links();
    bpf_object__close(obj);
    return 0;
}
