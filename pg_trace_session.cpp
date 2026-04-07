#include "pg_trace_session.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace {
enum class request_kind {
    simple_query,
    prepare,
    execute,
};

enum operator_id : uint16_t {
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

struct query_state {
    request_kind kind;
    std::string tag;
    std::string query;
    uint64_t start_ns;
    uint64_t batch_id;
    struct phase_timing {
        uint8_t phase;
        uint64_t start_ns;
        uint64_t end_ns;
        uint32_t pid;
        uint32_t tid;
    };
    struct operator_call {
        uint16_t op_id;
        uint16_t depth;
        std::string name;
        uint64_t start_ns;
        uint64_t end_ns;
        uint32_t tid;
    };
    struct seq_scan_step {
        uint8_t step_id;
        uint8_t seq_scan_depth;
        uint64_t start_ns;
        uint64_t end_ns;
        uint32_t tid;
    };
    struct lwlock_wait {
        uint16_t op_id;
        uint16_t op_depth;
        uint8_t step_id;
        uint8_t step_depth;
        uint64_t start_ns;
        uint64_t end_ns;
        uint32_t tid;
    };
    std::vector<phase_timing> phases;
    std::vector<operator_call> operators;
    std::vector<seq_scan_step> seq_scan_steps;
    std::vector<lwlock_wait> lwlock_waits;
};

struct simple_batch_state {
    uint64_t batch_id;
    size_t pending_count;
};

struct connection_key {
    uint32_t pid;
    int fd;

    bool operator==(const connection_key& other) const {
        return pid == other.pid && fd == other.fd;
    }
};

struct connection_key_hash {
    size_t operator()(const connection_key& key) const {
        return (static_cast<size_t>(key.pid) << 32) ^ static_cast<uint32_t>(key.fd);
    }
};

struct connection_state {
    bool protocol_confirmed = false;
    std::string inbound;
    std::string outbound;
    std::deque<query_state> pending_queries;
    std::deque<simple_batch_state> pending_simple_batches;
    std::unordered_map<std::string, std::string> prepared_statements;
    std::unordered_map<std::string, std::string> portals;
};

static uint32_t read_be32(const unsigned char* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           (static_cast<uint32_t>(p[3]));
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

static bool is_known_frontend_tag(unsigned char tag) {
    switch (tag) {
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'H':
    case 'P':
    case 'Q':
    case 'S':
    case 'X':
    case 'd':
    case 'f':
    case 'p':
        return true;
    default:
        return false;
    }
}

static bool is_known_backend_tag(unsigned char tag) {
    switch (tag) {
    case '1':
    case '2':
    case '3':
    case 'A':
    case 'C':
    case 'D':
    case 'E':
    case 'G':
    case 'H':
    case 'I':
    case 'K':
    case 'N':
    case 'R':
    case 'S':
    case 'T':
    case 'V':
    case 'W':
    case 'Z':
    case 'c':
    case 'd':
    case 'n':
    case 's':
    case 't':
        return true;
    default:
        return false;
    }
}

static bool has_sql_content(std::string_view sql) {
    for (size_t i = 0; i < sql.size(); ++i) {
        char c = sql[i];
        char next = (i + 1 < sql.size()) ? sql[i + 1] : '\0';

        if (std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        if (c == '-' && next == '-') {
            i += 2;
            while (i < sql.size() && sql[i] != '\n') {
                ++i;
            }
            continue;
        }
        if (c == '/' && next == '*') {
            i += 2;
            while (i + 1 < sql.size() && !(sql[i] == '*' && sql[i + 1] == '/')) {
                ++i;
            }
            if (i + 1 < sql.size()) {
                ++i;
            }
            continue;
        }
        return true;
    }
    return false;
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
            if (!stmt.empty() && has_sql_content(stmt)) {
                statements.emplace_back(stmt);
            }
            start = i + 1;
        }
    }

    std::string_view stmt = trim_sql(sql.substr(start));
    if (!stmt.empty() && has_sql_content(stmt)) {
        statements.emplace_back(stmt);
    }
    return statements;
}

static const char* phase_name(uint8_t phase) {
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

static const char* operator_name(uint16_t op_id) {
    switch (op_id) {
    case OP_RESULT: return "Result";
    case OP_SEQ_SCAN: return "Seq Scan";
    case OP_INDEX_SCAN: return "Index Scan";
    case OP_INDEX_ONLY_SCAN: return "Index Only Scan";
    case OP_BITMAP_INDEX_SCAN: return "Bitmap Index Scan";
    case OP_BITMAP_HEAP_SCAN: return "Bitmap Heap Scan";
    case OP_TID_SCAN: return "Tid Scan";
    case OP_SUBQUERY_SCAN: return "Subquery Scan";
    case OP_FUNCTION_SCAN: return "Function Scan";
    case OP_VALUES_SCAN: return "Values Scan";
    case OP_CTE_SCAN: return "CTE Scan";
    case OP_WORKTABLE_SCAN: return "WorkTable Scan";
    case OP_NEST_LOOP: return "Nested Loop";
    case OP_MERGE_JOIN: return "Merge Join";
    case OP_HASH_JOIN: return "Hash Join";
    case OP_MATERIALIZE: return "Materialize";
    case OP_SORT: return "Sort";
    case OP_GROUP: return "Group";
    case OP_AGGREGATE: return "Aggregate";
    case OP_WINDOW_AGG: return "WindowAgg";
    case OP_UNIQUE: return "Unique";
    case OP_APPEND: return "Append";
    case OP_MERGE_APPEND: return "Merge Append";
    case OP_LIMIT: return "Limit";
    case OP_LOCK_ROWS: return "LockRows";
    case OP_MODIFY_TABLE: return "ModifyTable";
    case OP_HASH: return "Hash";
    case OP_GATHER: return "Gather";
    case OP_GATHER_MERGE: return "Gather Merge";
    case OP_SET_OP: return "SetOp";
    case OP_PROJECT_SET: return "ProjectSet";
    case OP_MEMOIZE: return "Memoize";
    case OP_BITMAP_AND: return "BitmapAnd";
    case OP_BITMAP_OR: return "BitmapOr";
    default: return "Unknown Operator";
    }
}

static const char* seq_scan_step_name(uint8_t step_id) {
    switch (step_id) {
    case 1:
        return "exec_scan";
    default:
        return "unknown_step";
    }
}
} // namespace

struct PgTraceSession::impl {
    std::unordered_map<connection_key, connection_state, connection_key_hash> connections;
    uint64_t realtime_offset_ns = 0;
    uint64_t next_batch_id = 1;
    std::vector<std::string> completed_queries;

    std::string format_timestamp(uint64_t mono_ns) const {
        uint64_t real_ns = mono_ns + realtime_offset_ns;
        time_t sec = static_cast<time_t>(real_ns / 1000000000ull);
        long millis = static_cast<long>((real_ns % 1000000000ull) / 1000000ull);
        struct tm tm_buf;
        localtime_r(&sec, &tm_buf);

        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);

        char out[80];
        std::snprintf(out, sizeof(out), "%s.%03ld", buf, millis);
        return out;
    }

    static double duration_ms(uint64_t start_ns, uint64_t end_ns) {
        return static_cast<double>(end_ns - start_ns) / 1000000.0;
    }

    static void append_tree_leaf(std::ostringstream& out, const std::string& prefix, bool last,
                                 const char* key, const std::string& value) {
        out << prefix << (last ? "`-- " : "|-- ") << key << ": " << value << '\n';
    }

    static void append_tree_leaf(std::ostringstream& out, const std::string& prefix, bool last,
                                 const char* key, double value) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.3f", value);
        out << prefix << (last ? "`-- " : "|-- ") << key << ": " << buf << '\n';
    }

    static void append_tree_leaf(std::ostringstream& out, const std::string& prefix, bool last,
                                 const char* key, unsigned value) {
        out << prefix << (last ? "`-- " : "|-- ") << key << ": " << value << '\n';
    }

    static connection_key make_connection_key(uint32_t pid, int fd) {
        return connection_key{.pid = pid, .fd = fd};
    }

    query_state* current_query_for_pid(uint32_t pid) {
        for (auto& [key, conn] : connections) {
            if (key.pid == pid && !conn.pending_queries.empty()) {
                return &conn.pending_queries.front();
            }
        }
        return nullptr;
    }

    void queue_query(const connection_key& key, request_kind kind, const char* tag, const char* query, size_t len,
                     uint64_t ts_ns, uint64_t batch_id = 0) {
        if (len == 0) {
            return;
        }
        auto& conn = connections[key];
        conn.pending_queries.push_back(query_state{
            .kind = kind,
            .tag = tag,
            .query = std::string(query, len),
            .start_ns = ts_ns,
            .batch_id = batch_id,
        });
    }

    void append_lwlock_waits(std::ostringstream& out, const query_state& query, uint16_t op_id, uint16_t op_depth,
                             uint8_t step_id, uint8_t step_depth, const std::string& prefix,
                             bool last_section) const {
        std::vector<const query_state::lwlock_wait*> waits;
        for (const auto& wait : query.lwlock_waits) {
            if (wait.op_id == op_id && wait.op_depth == op_depth &&
                wait.step_id == step_id && wait.step_depth == step_depth) {
                waits.push_back(&wait);
            }
        }
        if (waits.empty()) {
            return;
        }

        std::sort(waits.begin(), waits.end(),
                  [](const auto* lhs, const auto* rhs) {
                      if (lhs->start_ns != rhs->start_ns) {
                          return lhs->start_ns < rhs->start_ns;
                      }
                      if (lhs->end_ns != rhs->end_ns) {
                          return lhs->end_ns < rhs->end_ns;
                      }
                      return lhs->tid < rhs->tid;
                  });

        out << prefix << (last_section ? "`-- " : "|-- ") << "lwlock_waits\n";
        const std::string wait_prefix = prefix + (last_section ? "    " : "|   ");
        for (size_t i = 0; i < waits.size(); ++i) {
            const auto& wait = *waits[i];
            const bool wait_last = i + 1 == waits.size();
            const char* child_prefix = wait_last ? "    " : "|   ";
            out << wait_prefix << (wait_last ? "`-- " : "|-- ") << "LWLockQueueSelf\n";
            const std::string details_prefix = wait_prefix + child_prefix;
            append_tree_leaf(out, details_prefix, false, "start_time", format_timestamp(wait.start_ns));
            append_tree_leaf(out, details_prefix, false, "end_time", format_timestamp(wait.end_ns));
            append_tree_leaf(out, details_prefix, false, "duration_ms", duration_ms(wait.start_ns, wait.end_ns));
            append_tree_leaf(out, details_prefix, true, "tid", wait.tid);
        }
    }

    void append_seq_scan_steps(std::ostringstream& out, const query_state& query,
                               const query_state::operator_call& op, const std::string& prefix,
                               bool last_section) const {
        std::vector<const query_state::seq_scan_step*> steps;
        for (const auto& step : query.seq_scan_steps) {
            if (step.tid == op.tid && step.seq_scan_depth == op.depth &&
                step.start_ns >= op.start_ns && step.end_ns <= op.end_ns) {
                steps.push_back(&step);
            }
        }
        if (steps.empty()) {
            return;
        }

        std::sort(steps.begin(), steps.end(),
                  [](const auto* lhs, const auto* rhs) {
                      if (lhs->start_ns != rhs->start_ns) {
                          return lhs->start_ns < rhs->start_ns;
                      }
                      if (lhs->end_ns != rhs->end_ns) {
                          return lhs->end_ns < rhs->end_ns;
                      }
                      return lhs->step_id < rhs->step_id;
                  });

        out << prefix << (last_section ? "`-- " : "|-- ") << "steps\n";
        const std::string step_prefix = prefix + (last_section ? "    " : "|   ");
        for (size_t i = 0; i < steps.size(); ++i) {
            const auto& step = *steps[i];
            const bool step_last = i + 1 == steps.size();
            const char* child_prefix = step_last ? "    " : "|   ";
            out << step_prefix << (step_last ? "`-- " : "|-- ") << seq_scan_step_name(step.step_id) << '\n';
            const std::string details_prefix = step_prefix + child_prefix;
            append_tree_leaf(out, details_prefix, false, "start_time", format_timestamp(step.start_ns));
            append_tree_leaf(out, details_prefix, false, "end_time", format_timestamp(step.end_ns));
            append_tree_leaf(out, details_prefix, false, "duration_ms", duration_ms(step.start_ns, step.end_ns));
            append_tree_leaf(out, details_prefix, false, "tid", step.tid);
            append_lwlock_waits(out, query, op.op_id, op.depth, step.step_id, step.seq_scan_depth,
                                details_prefix, true);
        }
    }

    void append_operator_calls(std::ostringstream& out, const query_state& query, const std::string& prefix,
                               bool last_section) const {
        if (query.operators.empty()) {
            return;
        }

        out << prefix << (last_section ? "`-- " : "|-- ") << "operators\n";
        const std::string operator_prefix = prefix + (last_section ? "    " : "|   ");
        std::vector<const query_state::operator_call*> ordered_ops;
        ordered_ops.reserve(query.operators.size());
        for (const auto& op : query.operators) {
            ordered_ops.push_back(&op);
        }
        std::sort(ordered_ops.begin(), ordered_ops.end(),
                  [](const auto* lhs, const auto* rhs) {
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
            const bool op_last = i + 1 == ordered_ops.size();
            const bool print_steps = op.op_id == OP_SEQ_SCAN;
            out << operator_prefix << (op_last ? "`-- " : "|-- ") << op.name << '\n';
            const std::string details_prefix = operator_prefix + (op_last ? "    " : "|   ");
            append_tree_leaf(out, details_prefix, false, "start_time", format_timestamp(op.start_ns));
            append_tree_leaf(out, details_prefix, false, "end_time", format_timestamp(op.end_ns));
            append_tree_leaf(out, details_prefix, false, "duration_ms", duration_ms(op.start_ns, op.end_ns));
            append_tree_leaf(out, details_prefix, print_steps ? false : false, "tid", op.tid);
            append_lwlock_waits(out, query, op.op_id, op.depth, 0, 0, details_prefix, !print_steps);
            if (print_steps) {
                append_seq_scan_steps(out, query, op, details_prefix, true);
            }
        }
    }

    std::string render_query_timing(const query_state& query, uint64_t finish_ns) const {
        std::ostringstream out;
        out << query.tag << '\n';
        append_tree_leaf(out, "", false, "sql", query.query);
        append_tree_leaf(out, "", false, "start_time", format_timestamp(query.start_ns));
        append_tree_leaf(out, "", false, "end_time", format_timestamp(finish_ns));

        if (query.phases.empty()) {
            append_tree_leaf(out, "", true, "duration_ms", duration_ms(query.start_ns, finish_ns));
            return out.str();
        }

        append_tree_leaf(out, "", false, "duration_ms", duration_ms(query.start_ns, finish_ns));
        out << "`-- trace\n";
        constexpr const char* trace_prefix = "    ";
        for (size_t i = 0; i < query.phases.size(); ++i) {
            const auto& phase = query.phases[i];
            const bool phase_last = i + 1 == query.phases.size();
            const char* branch = phase_last ? "`-- " : "|-- ";
            const char* child_prefix = phase_last ? "        " : "    |   ";
            const bool print_operators = phase.phase == QUERY_PHASE_EXECUTE && !query.operators.empty();

            out << trace_prefix << branch << phase_name(phase.phase) << '\n';
            append_tree_leaf(out, child_prefix, false, "start_time", format_timestamp(phase.start_ns));
            append_tree_leaf(out, child_prefix, false, "end_time", format_timestamp(phase.end_ns));
            append_tree_leaf(out, child_prefix, false, "duration_ms", duration_ms(phase.start_ns, phase.end_ns));
            append_tree_leaf(out, child_prefix, false, "pid", phase.pid);
            append_tree_leaf(out, child_prefix, print_operators ? false : true, "tid", phase.tid);
            if (print_operators) {
                append_operator_calls(out, query, child_prefix, true);
            }
        }
        return out.str();
    }

    void finish_query(const connection_key& key, request_kind kind, uint64_t ts_ns) {
        auto it = connections.find(key);
        if (it == connections.end()) {
            return;
        }

        auto& pending = it->second.pending_queries;
        if (pending.empty() || pending.front().kind != kind) {
            return;
        }

        query_state query = std::move(pending.front());
        pending.pop_front();
        completed_queries.push_back(render_query_timing(query, ts_ns));

        if (kind == request_kind::simple_query) {
            auto& batches = it->second.pending_simple_batches;
            if (!batches.empty() && batches.front().batch_id == query.batch_id && batches.front().pending_count > 0) {
                --batches.front().pending_count;
            }
        }
    }

    void finish_front_query(const connection_key& key, uint64_t ts_ns) {
        auto it = connections.find(key);
        if (it == connections.end() || it->second.pending_queries.empty()) {
            return;
        }
        finish_query(key, it->second.pending_queries.front().kind, ts_ns);
    }

    void queue_simple_query_batch(const connection_key& key, std::string_view sql, uint64_t ts_ns) {
        std::vector<std::string> statements = split_simple_query(sql);
        if (statements.empty()) {
            return;
        }

        auto& conn = connections[key];
        uint64_t batch_id = next_batch_id++;
        conn.pending_simple_batches.push_back(simple_batch_state{
            .batch_id = batch_id,
            .pending_count = statements.size(),
        });

        for (const std::string& statement : statements) {
            queue_query(key, request_kind::simple_query, "QUERY",
                        statement.data(), statement.size(), ts_ns, batch_id);
        }
    }

    void finish_simple_query_batch(const connection_key& key, uint64_t ts_ns) {
        auto it = connections.find(key);
        if (it == connections.end()) {
            return;
        }

        auto& conn = it->second;
        if (conn.pending_simple_batches.empty()) {
            return;
        }

        auto& batch = conn.pending_simple_batches.front();
        while (batch.pending_count > 0 && !conn.pending_queries.empty()) {
            query_state& query = conn.pending_queries.front();
            if (query.kind != request_kind::simple_query || query.batch_id != batch.batch_id) {
                break;
            }
            completed_queries.push_back(render_query_timing(query, ts_ns));
            conn.pending_queries.pop_front();
            if (batch.pending_count > 0) {
                --batch.pending_count;
            }
        }
        conn.pending_simple_batches.pop_front();
    }

    bool parse_frontend_messages(uint32_t pid, int fd, const unsigned char* data, size_t len, uint64_t ts_ns) {
        if (len == 0) {
            return false;
        }

        const connection_key key = make_connection_key(pid, fd);
        auto& conn = connections[key];
        auto& buf = conn.inbound;
        const bool had_partial = !buf.empty();
        if (!had_partial) {
            const unsigned char first = data[0];
            if (first >= 'A' && first <= 'Z' && !is_known_frontend_tag(first)) {
                return false;
            }
        }
        buf.append(reinterpret_cast<const char*>(data), len);

        constexpr size_t kMaxBuffer = 1u << 20;
        if (buf.size() > kMaxBuffer) {
            buf.clear();
            return false;
        }

        bool accepted = true;
        conn.protocol_confirmed = true;

        while (true) {
            if (buf.size() < 4) {
                return accepted;
            }

            unsigned char first = static_cast<unsigned char>(buf[0]);
            bool typed = (first >= 'A' && first <= 'Z');
            size_t header = typed ? 5 : 4;
            if (buf.size() < header) {
                return accepted;
            }

            const unsigned char* p = reinterpret_cast<const unsigned char*>(buf.data());
            uint32_t msg_len = typed ? read_be32(p + 1) : read_be32(p);
            if (msg_len < 4) {
                buf.clear();
                return false;
            }

            size_t total = typed ? (1 + msg_len) : msg_len;
            if (buf.size() < total) {
                return accepted;
            }

            if (typed && (first == 'Q' || first == 'P')) {
                const char* payload = reinterpret_cast<const char*>(p + 5);
                size_t payload_len = msg_len - 4;
                if (first == 'Q') {
                    const char* end = static_cast<const char*>(std::memchr(payload, '\0', payload_len));
                    size_t qlen = end ? static_cast<size_t>(end - payload) : payload_len;
                    queue_simple_query_batch(key, std::string_view(payload, qlen), ts_ns);
                } else {
                    const char* name_end = static_cast<const char*>(std::memchr(payload, '\0', payload_len));
                    if (name_end) {
                        auto& conn = connections[key];
                        size_t remaining = payload_len - static_cast<size_t>(name_end - payload) - 1;
                        const char* query = name_end + 1;
                        const char* q_end = static_cast<const char*>(std::memchr(query, '\0', remaining));
                        size_t qlen = q_end ? static_cast<size_t>(q_end - query) : remaining;
                        std::string stmt_name(payload, static_cast<size_t>(name_end - payload));
                        conn.prepared_statements[stmt_name] = std::string(query, qlen);
                        queue_query(key, request_kind::prepare, "PREPARE", query, qlen, ts_ns);
                    }
                }
            } else if (typed && first == 'B') {
                const char* payload = reinterpret_cast<const char*>(p + 5);
                size_t payload_len = msg_len - 4;
                const char* portal_end = static_cast<const char*>(std::memchr(payload, '\0', payload_len));
                if (portal_end) {
                    size_t remaining = payload_len - static_cast<size_t>(portal_end - payload) - 1;
                    const char* statement = portal_end + 1;
                    const char* statement_end = static_cast<const char*>(std::memchr(statement, '\0', remaining));
                    if (statement_end) {
                        connections[key].portals[std::string(payload, static_cast<size_t>(portal_end - payload))] =
                            std::string(statement, static_cast<size_t>(statement_end - statement));
                    }
                }
            } else if (typed && first == 'E') {
                const char* payload = reinterpret_cast<const char*>(p + 5);
                size_t payload_len = msg_len - 4;
                const char* portal_end = static_cast<const char*>(std::memchr(payload, '\0', payload_len));
                if (portal_end) {
                    auto& conn = connections[key];
                    std::string portal(payload, static_cast<size_t>(portal_end - payload));
                    auto portal_it = conn.portals.find(portal);
                    if (portal_it != conn.portals.end()) {
                        auto stmt_it = conn.prepared_statements.find(portal_it->second);
                        if (stmt_it != conn.prepared_statements.end()) {
                            queue_query(key, request_kind::execute, "EXECUTE",
                                        stmt_it->second.data(), stmt_it->second.size(), ts_ns);
                        }
                    }
                }
            }

            buf.erase(0, total);
        }
    }

    bool parse_backend_messages(uint32_t pid, int fd, const unsigned char* data, size_t len, uint64_t ts_ns) {
        if (len == 0) {
            return false;
        }

        const connection_key key = make_connection_key(pid, fd);
        auto conn_it = connections.find(key);
        if (conn_it == connections.end()) {
            return false;
        }
        auto& conn = conn_it->second;
        auto& buf = conn.outbound;
        if (buf.empty() && (!conn.protocol_confirmed || !is_known_backend_tag(data[0]))) {
            return false;
        }
        buf.append(reinterpret_cast<const char*>(data), len);

        constexpr size_t kMaxBuffer = 1u << 20;
        if (buf.size() > kMaxBuffer) {
            buf.clear();
            return false;
        }

        bool accepted = true;

        while (true) {
            if (buf.size() < 5) {
                return accepted;
            }

            const unsigned char* p = reinterpret_cast<const unsigned char*>(buf.data());
            uint32_t msg_len = read_be32(p + 1);
            if (msg_len < 4) {
                buf.clear();
                return false;
            }

            size_t total = 1 + msg_len;
            if (buf.size() < total) {
                return accepted;
            }

            unsigned char tag = p[0];
            if (tag == 'C' || tag == 'E' || tag == 'I') {
                finish_front_query(key, ts_ns);
            } else if (tag == '1') {
                finish_query(key, request_kind::prepare, ts_ns);
            } else if (tag == 's') {
                finish_query(key, request_kind::execute, ts_ns);
            } else if (tag == 'Z') {
                finish_simple_query_batch(key, ts_ns);
            }

            buf.erase(0, total);
        }
    }

    int handle_event(const void* data, size_t data_sz) {
        if (data == nullptr || data_sz < sizeof(event_header)) {
            return -1;
        }

        const auto* header = static_cast<const event_header*>(data);
        switch (header->type) {
        case EVENT_TYPE_IO: {
            if (data_sz < sizeof(read_event)) {
                return -1;
            }
            const auto& event = *static_cast<const read_event*>(data);
            if (event.len > 0) {
                if (event.direction == IO_DIRECTION_IN) {
                    parse_frontend_messages(event.pid, event.fd, event.data, static_cast<size_t>(event.len), event.ts_ns);
                } else if (event.direction == IO_DIRECTION_OUT) {
                    parse_backend_messages(event.pid, event.fd, event.data, static_cast<size_t>(event.len), event.ts_ns);
                }
            }
            return 0;
        }
        case EVENT_TYPE_PHASE: {
            if (data_sz < sizeof(phase_event)) {
                return -1;
            }
            const auto& event = *static_cast<const phase_event*>(data);
            query_state* query = current_query_for_pid(event.pid);
            if (!query) {
                return 0;
            }
            query->phases.push_back(query_state::phase_timing{
                .phase = event.phase,
                .start_ns = event.start_ns,
                .end_ns = event.end_ns,
                .pid = event.pid,
                .tid = event.tid,
            });
            return 0;
        }
        case EVENT_TYPE_OPERATOR: {
            if (data_sz < sizeof(operator_event)) {
                return -1;
            }
            const auto& event = *static_cast<const operator_event*>(data);
            query_state* query = current_query_for_pid(event.pid);
            if (!query || event.end_ns < event.start_ns) {
                return 0;
            }
            query->operators.push_back(query_state::operator_call{
                .op_id = event.op_id,
                .depth = event.depth,
                .name = operator_name(event.op_id),
                .start_ns = event.start_ns,
                .end_ns = event.end_ns,
                .tid = event.tid,
            });
            return 0;
        }
        case EVENT_TYPE_SEQ_SCAN_STEP: {
            if (data_sz < sizeof(seq_scan_step_event)) {
                return -1;
            }
            const auto& event = *static_cast<const seq_scan_step_event*>(data);
            query_state* query = current_query_for_pid(event.pid);
            if (!query || event.end_ns < event.start_ns) {
                return 0;
            }
            query->seq_scan_steps.push_back(query_state::seq_scan_step{
                .step_id = event.step_id,
                .seq_scan_depth = event.seq_scan_depth,
                .start_ns = event.start_ns,
                .end_ns = event.end_ns,
                .tid = event.tid,
            });
            return 0;
        }
        case EVENT_TYPE_LWLOCK_WAIT: {
            if (data_sz < sizeof(lwlock_wait_event)) {
                return -1;
            }
            const auto& event = *static_cast<const lwlock_wait_event*>(data);
            query_state* query = current_query_for_pid(event.pid);
            if (!query || event.end_ns < event.start_ns) {
                return 0;
            }
            query->lwlock_waits.push_back(query_state::lwlock_wait{
                .op_id = event.op_id,
                .op_depth = event.op_depth,
                .step_id = event.step_id,
                .step_depth = event.step_depth,
                .start_ns = event.start_ns,
                .end_ns = event.end_ns,
                .tid = event.tid,
            });
            return 0;
        }
        default:
            printf("invalid event");
            return -1;
        }
    }
};

PgTraceSession::PgTraceSession() : impl_(new impl()) {}
PgTraceSession::~PgTraceSession() { delete impl_; }
PgTraceSession::PgTraceSession(PgTraceSession&& other) noexcept : impl_(other.impl_) { other.impl_ = nullptr; }
PgTraceSession& PgTraceSession::operator=(PgTraceSession&& other) noexcept {
    if (this != &other) {
        delete impl_;
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

void PgTraceSession::set_realtime_offset_ns(uint64_t realtime_offset_ns) {
    impl_->realtime_offset_ns = realtime_offset_ns;
}

int PgTraceSession::handle_event(const void* data, size_t data_sz) {
    return impl_->handle_event(data, data_sz);
}

std::vector<std::string> PgTraceSession::take_completed_queries() {
    std::vector<std::string> out = std::move(impl_->completed_queries);
    impl_->completed_queries.clear();
    return out;
}
