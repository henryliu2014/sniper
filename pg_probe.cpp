#include "pg_probe.h"
#include "pg_trace_session.h"

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
#include <string>
#include <algorithm>

extern const unsigned char pg_probe_bpf_blob_start[];
extern const unsigned char pg_probe_bpf_blob_end[];

namespace {
volatile sig_atomic_t g_stop = 0;

void handle_sigint(int) {
    g_stop = 1;
}

static __u64 timespec_to_ns(const timespec& ts) {
    return static_cast<__u64>(ts.tv_sec) * 1000000000ull + static_cast<__u64>(ts.tv_nsec);
}
PgTraceSession g_trace_session;

int handle_event(void* /*ctx*/, void* data, size_t data_sz) {
    if (g_trace_session.handle_event(data, data_sz) != 0) {
        printf("no header type");
        return 0;
    }

    for (const std::string& rendered_query : g_trace_session.take_completed_queries()) {
        fputs(rendered_query.c_str(), stdout);
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
    struct paired_probe_spec {
        const char* enter_prog_name;
        const char* exit_prog_name;
    };
    struct tracepoint_probe_spec : paired_probe_spec {
        const char* category;
        const char* enter_event_name;
        const char* exit_event_name;
    };
    struct uprobe_probe_spec : paired_probe_spec {
        const char* func_name;
    };
    static constexpr tracepoint_probe_spec tracepoint_specs[] = {
        {{"trace_sys_enter_recvfrom", "trace_sys_exit_recvfrom"}, "syscalls", "sys_enter_recvfrom", "sys_exit_recvfrom"},
        {{"trace_sys_enter_read", "trace_sys_exit_read"}, "syscalls", "sys_enter_read", "sys_exit_read"},
        {{"trace_sys_enter_write", "trace_sys_exit_write"}, "syscalls", "sys_enter_write", "sys_exit_write"},
        {{"trace_sys_enter_sendto", "trace_sys_exit_sendto"}, "syscalls", "sys_enter_sendto", "sys_exit_sendto"},
    };
    static constexpr uprobe_probe_spec phase_specs[] = {
        {{"trace_pg_parse_query_enter", "trace_pg_parse_query_exit"}, "pg_parse_query"},
        {{"trace_pg_analyze_and_rewrite_fixedparams_enter", "trace_pg_analyze_and_rewrite_fixedparams_exit"},
         "pg_analyze_and_rewrite_fixedparams"},
        {{"trace_pg_analyze_and_rewrite_varparams_enter", "trace_pg_analyze_and_rewrite_varparams_exit"},
         "pg_analyze_and_rewrite_varparams"},
        {{"trace_pg_analyze_and_rewrite_withcb_enter", "trace_pg_analyze_and_rewrite_withcb_exit"},
         "pg_analyze_and_rewrite_withcb"},
        {{"trace_pg_plan_queries_enter", "trace_pg_plan_queries_exit"}, "pg_plan_queries"},
        {{"trace_PortalRun_enter", "trace_PortalRun_exit"}, "PortalRun"},
    };
    struct operator_probe_spec {
        const char* enter_prog_name;
        const char* exit_prog_name;
        const char* func_name;
    };
    struct seq_scan_step_probe_spec {
        const char* enter_prog_name;
        const char* exit_prog_name;
        const char* func_name;
    };
    struct lwlock_wait_probe_spec {
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
    static constexpr seq_scan_step_probe_spec seq_scan_step_specs[] = {
        {"trace_ExecScan_enter", "trace_ExecScan_exit", "ExecScan"},
    };
    static constexpr lwlock_wait_probe_spec lwlock_wait_specs[] = {
        {"trace_LWLockQueueSelf_enter", "trace_LWLockQueueSelf_exit", "LWLockQueueSelf"},
    };
    std::vector<struct bpf_program*> prog_tracepoint_enters;
    std::vector<struct bpf_program*> prog_tracepoint_exits;
    std::vector<struct bpf_program*> prog_phase_enters;
    std::vector<struct bpf_program*> prog_phase_exits;
    std::vector<struct bpf_program*> prog_operator_enters;
    std::vector<struct bpf_program*> prog_operator_exits;
    std::vector<struct bpf_program*> prog_seq_scan_step_enters;
    std::vector<struct bpf_program*> prog_seq_scan_step_exits;
    std::vector<struct bpf_program*> prog_lwlock_wait_enters;
    std::vector<struct bpf_program*> prog_lwlock_wait_exits;
    std::vector<struct bpf_link*> link_tracepoint_enters;
    std::vector<struct bpf_link*> link_tracepoint_exits;
    std::vector<struct bpf_link*> link_phase_enters;
    std::vector<struct bpf_link*> link_phase_exits;
    std::vector<struct bpf_link*> link_operator_enters;
    std::vector<struct bpf_link*> link_operator_exits;
    std::vector<struct bpf_link*> link_seq_scan_step_enters;
    std::vector<struct bpf_link*> link_seq_scan_step_exits;
    std::vector<struct bpf_link*> link_lwlock_wait_enters;
    std::vector<struct bpf_link*> link_lwlock_wait_exits;
    struct ring_buffer* rb = nullptr;
    std::string postgres_binary;
    auto destroy_links = [&]() {
        auto destroy_link_vector = [](const auto& links) {
            for (auto it = links.rbegin(); it != links.rend(); ++it) {
                bpf_link__destroy(*it);
            }
        };
        destroy_link_vector(link_operator_exits);
        destroy_link_vector(link_operator_enters);
        destroy_link_vector(link_lwlock_wait_exits);
        destroy_link_vector(link_lwlock_wait_enters);
        destroy_link_vector(link_seq_scan_step_exits);
        destroy_link_vector(link_seq_scan_step_enters);
        destroy_link_vector(link_phase_exits);
        destroy_link_vector(link_phase_enters);
        destroy_link_vector(link_tracepoint_exits);
        destroy_link_vector(link_tracepoint_enters);
    };

    timespec realtime_ts {};
    timespec monotonic_ts {};
    if (clock_gettime(CLOCK_REALTIME, &realtime_ts) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic_ts) != 0) {
        fprintf(stderr, "pg_probe: failed to read clocks\n");
        return -1;
    }
    g_trace_session.set_realtime_offset_ns(timespec_to_ns(realtime_ts) - timespec_to_ns(monotonic_ts));
    postgres_binary = read_proc_exe(postgres_pids.front());
    if (postgres_binary.empty()) {
        fprintf(stderr, "pg_probe: failed to resolve postgres binary path\n");
        return -1;
    }

    obj = bpf_object__open_mem(
        pg_probe_bpf_blob_start,
        static_cast<size_t>(pg_probe_bpf_blob_end - pg_probe_bpf_blob_start),
        nullptr);
    if (!obj) {
        fprintf(stderr, "pg_probe: failed to open BPF object\n");
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "pg_probe: failed to load BPF object\n");
        bpf_object__close(obj);
        return -1;
    }

    prog_tracepoint_enters.reserve(std::size(tracepoint_specs));
    prog_tracepoint_exits.reserve(std::size(tracepoint_specs));
    for (const auto& spec : tracepoint_specs) {
        prog_tracepoint_enters.push_back(bpf_object__find_program_by_name(obj, spec.enter_prog_name));
        prog_tracepoint_exits.push_back(bpf_object__find_program_by_name(obj, spec.exit_prog_name));
    }
    prog_phase_enters.reserve(std::size(phase_specs));
    prog_phase_exits.reserve(std::size(phase_specs));
    for (const auto& spec : phase_specs) {
        prog_phase_enters.push_back(bpf_object__find_program_by_name(obj, spec.enter_prog_name));
        prog_phase_exits.push_back(bpf_object__find_program_by_name(obj, spec.exit_prog_name));
    }
    prog_operator_enters.reserve(std::size(operator_specs));
    prog_operator_exits.reserve(std::size(operator_specs));
    for (const auto& spec : operator_specs) {
        prog_operator_enters.push_back(bpf_object__find_program_by_name(obj, spec.enter_prog_name));
        prog_operator_exits.push_back(bpf_object__find_program_by_name(obj, spec.exit_prog_name));
    }
    prog_seq_scan_step_enters.reserve(std::size(seq_scan_step_specs));
    prog_seq_scan_step_exits.reserve(std::size(seq_scan_step_specs));
    for (const auto& spec : seq_scan_step_specs) {
        prog_seq_scan_step_enters.push_back(bpf_object__find_program_by_name(obj, spec.enter_prog_name));
        prog_seq_scan_step_exits.push_back(bpf_object__find_program_by_name(obj, spec.exit_prog_name));
    }
    prog_lwlock_wait_enters.reserve(std::size(lwlock_wait_specs));
    prog_lwlock_wait_exits.reserve(std::size(lwlock_wait_specs));
    for (const auto& spec : lwlock_wait_specs) {
        prog_lwlock_wait_enters.push_back(bpf_object__find_program_by_name(obj, spec.enter_prog_name));
        prog_lwlock_wait_exits.push_back(bpf_object__find_program_by_name(obj, spec.exit_prog_name));
    }
    auto all_programs_found = [](const auto& programs) {
        return std::all_of(programs.begin(), programs.end(),
                           [](const bpf_program* prog) { return prog != nullptr; });
    };
    if (!all_programs_found(prog_tracepoint_enters) || !all_programs_found(prog_tracepoint_exits) ||
        !all_programs_found(prog_phase_enters) || !all_programs_found(prog_phase_exits)) {
        fprintf(stderr, "pg_probe: program not found\n");
        bpf_object__close(obj);
        return -1;
    }

    link_tracepoint_enters.reserve(std::size(tracepoint_specs));
    link_tracepoint_exits.reserve(std::size(tracepoint_specs));
    for (size_t i = 0; i < std::size(tracepoint_specs); ++i) {
        link_tracepoint_enters.push_back(
            bpf_program__attach_tracepoint(prog_tracepoint_enters[i], tracepoint_specs[i].category, tracepoint_specs[i].enter_event_name));
        link_tracepoint_exits.push_back(
            bpf_program__attach_tracepoint(prog_tracepoint_exits[i], tracepoint_specs[i].category, tracepoint_specs[i].exit_event_name));
    }
    link_phase_enters.reserve(std::size(phase_specs));
    link_phase_exits.reserve(std::size(phase_specs));
    for (size_t i = 0; i < std::size(phase_specs); ++i) {
        link_phase_enters.push_back(
            attach_named_uprobe(prog_phase_enters[i], postgres_binary.c_str(), phase_specs[i].func_name, false));
        link_phase_exits.push_back(
            attach_named_uprobe(prog_phase_exits[i], postgres_binary.c_str(), phase_specs[i].func_name, true));
    }
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
    link_seq_scan_step_enters.reserve(std::size(seq_scan_step_specs));
    link_seq_scan_step_exits.reserve(std::size(seq_scan_step_specs));
    for (size_t i = 0; i < std::size(seq_scan_step_specs); ++i) {
        struct bpf_link* enter_link = nullptr;
        struct bpf_link* exit_link = nullptr;
        if (prog_seq_scan_step_enters[i]) {
            enter_link = attach_named_uprobe(prog_seq_scan_step_enters[i], postgres_binary.c_str(),
                                             seq_scan_step_specs[i].func_name, false);
            if (!link_is_ok(enter_link)) {
                enter_link = nullptr;
            }
        }
        if (prog_seq_scan_step_exits[i]) {
            exit_link = attach_named_uprobe(prog_seq_scan_step_exits[i], postgres_binary.c_str(),
                                            seq_scan_step_specs[i].func_name, true);
            if (!link_is_ok(exit_link)) {
                exit_link = nullptr;
            }
        }
        link_seq_scan_step_enters.push_back(enter_link);
        link_seq_scan_step_exits.push_back(exit_link);
    }
    link_lwlock_wait_enters.reserve(std::size(lwlock_wait_specs));
    link_lwlock_wait_exits.reserve(std::size(lwlock_wait_specs));
    for (size_t i = 0; i < std::size(lwlock_wait_specs); ++i) {
        struct bpf_link* enter_link = nullptr;
        struct bpf_link* exit_link = nullptr;
        if (prog_lwlock_wait_enters[i]) {
            enter_link = attach_named_uprobe(prog_lwlock_wait_enters[i], postgres_binary.c_str(),
                                             lwlock_wait_specs[i].func_name, false);
            if (!link_is_ok(enter_link)) {
                enter_link = nullptr;
            }
        }
        if (prog_lwlock_wait_exits[i]) {
            exit_link = attach_named_uprobe(prog_lwlock_wait_exits[i], postgres_binary.c_str(),
                                            lwlock_wait_specs[i].func_name, true);
            if (!link_is_ok(exit_link)) {
                exit_link = nullptr;
            }
        }
        link_lwlock_wait_enters.push_back(enter_link);
        link_lwlock_wait_exits.push_back(exit_link);
    }
    auto all_links_ok = [](const auto& links) {
        return std::all_of(links.begin(), links.end(),
                           [](bpf_link* link) { return link_is_ok(link); });
    };
    if (!all_links_ok(link_tracepoint_enters) || !all_links_ok(link_tracepoint_exits) ||
        !all_links_ok(link_phase_enters) || !all_links_ok(link_phase_exits)) {
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
