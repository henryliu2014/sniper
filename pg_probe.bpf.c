#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

struct read_args {
    __u64 buf;
    __s32 fd;
    __u8 direction;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct read_args);
} read_args_map SEC(".maps");

#define MAX_DATA 4096

enum event_type {
    EVENT_TYPE_IO = 1,
    EVENT_TYPE_PHASE = 2,
    EVENT_TYPE_OPERATOR = 3,
    EVENT_TYPE_SEQ_SCAN_STEP = 4,
    EVENT_TYPE_LWLOCK_WAIT = 5,
};

enum query_phase {
    QUERY_PHASE_PARSE = 1,
    QUERY_PHASE_ANALYZE = 2,
    QUERY_PHASE_PLAN = 3,
    QUERY_PHASE_EXECUTE = 4,
};

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
    unsigned char data[MAX_DATA];
};

struct phase_key {
    __u32 tid;
    __u8 phase;
} __attribute__((packed));

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
    __u16 depth;
    char comm[16];
};

struct seq_scan_step_event {
    __u32 type;
    __u64 start_ns;
    __u64 end_ns;
    __u32 pid;
    __u32 tid;
    __u8 step_id;
    __u8 seq_scan_depth;
    char comm[16];
};

struct lwlock_wait_event {
    __u32 type;
    __u64 start_ns;
    __u64 end_ns;
    __u32 pid;
    __u32 tid;
    __u16 op_id;
    __u16 op_depth;
    __u8 step_id;
    __u8 step_depth;
    char comm[16];
};

struct operator_depth_key {
    __u32 tid;
    __u16 op_id;
} __attribute__((packed));

struct operator_start_key {
    __u32 tid;
    __u16 op_id;
    __u16 depth;
} __attribute__((packed));

struct seq_scan_step_depth_key {
    __u32 tid;
    __u8 step_id;
    __u8 seq_scan_depth;
} __attribute__((packed));

struct seq_scan_step_start_key {
    __u32 tid;
    __u8 step_id;
    __u8 seq_scan_depth;
    __u16 depth;
} __attribute__((packed));

struct stack_depth_key {
    __u32 tid;
} __attribute__((packed));

struct active_operator_stack_key {
    __u32 tid;
    __u16 stack_depth;
} __attribute__((packed));

struct active_operator_stack_value {
    __u16 op_id;
    __u16 op_depth;
} __attribute__((packed));

struct active_step_stack_key {
    __u32 tid;
    __u16 stack_depth;
} __attribute__((packed));

struct active_step_stack_value {
    __u8 step_id;
    __u8 step_depth;
} __attribute__((packed));

struct lwlock_wait_key {
    __u32 tid;
    __u16 depth;
} __attribute__((packed));

enum operator_id {
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

enum io_direction {
    IO_DIRECTION_IN = 0,
    IO_DIRECTION_OUT = 1,
};

enum seq_scan_step_id {
    SEQ_SCAN_STEP_EXEC_SCAN = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, struct phase_key);
    __type(value, __u64);
} phase_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, struct operator_depth_key);
    __type(value, __u16);
} operator_depth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct operator_start_key);
    __type(value, __u64);
} operator_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct seq_scan_step_depth_key);
    __type(value, __u16);
} seq_scan_step_depth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct seq_scan_step_start_key);
    __type(value, __u64);
} seq_scan_step_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, struct stack_depth_key);
    __type(value, __u16);
} active_operator_stack_depth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct active_operator_stack_key);
    __type(value, struct active_operator_stack_value);
} active_operator_stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 40960);
    __type(key, struct stack_depth_key);
    __type(value, __u16);
} active_step_stack_depth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct active_step_stack_key);
    __type(value, struct active_step_stack_value);
} active_step_stack_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct lwlock_wait_key);
    __type(value, __u64);
} lwlock_wait_start_map SEC(".maps");

static __always_inline bool is_target_pid(__u32 pid) {
    return bpf_map_lookup_elem(&target_pids, &pid) != 0;
}

static __always_inline __u16 get_operator_stack_depth(__u32 tid) {
    struct stack_depth_key key = {
        .tid = tid,
    };
    __u16* depth = bpf_map_lookup_elem(&active_operator_stack_depth_map, &key);
    return depth ? *depth : 0;
}

static __always_inline void set_operator_stack_depth(__u32 tid, __u16 depth) {
    struct stack_depth_key key = {
        .tid = tid,
    };
    if (depth == 0) {
        bpf_map_delete_elem(&active_operator_stack_depth_map, &key);
    } else {
        bpf_map_update_elem(&active_operator_stack_depth_map, &key, &depth, BPF_ANY);
    }
}

static __always_inline __u16 get_step_stack_depth(__u32 tid) {
    struct stack_depth_key key = {
        .tid = tid,
    };
    __u16* depth = bpf_map_lookup_elem(&active_step_stack_depth_map, &key);
    return depth ? *depth : 0;
}

static __always_inline void set_step_stack_depth(__u32 tid, __u16 depth) {
    struct stack_depth_key key = {
        .tid = tid,
    };
    if (depth == 0) {
        bpf_map_delete_elem(&active_step_stack_depth_map, &key);
    } else {
        bpf_map_update_elem(&active_step_stack_depth_map, &key, &depth, BPF_ANY);
    }
}

static __always_inline int phase_enter(__u8 phase) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u64 ts_ns = bpf_ktime_get_ns();

    struct phase_key key = {
        .tid = tid,
        .phase = phase,
    };

    long ret = bpf_map_update_elem(&phase_start_map, &key, &ts_ns, BPF_ANY);

    if (ret != 0) {
        // 只有在 Map 满了（E2BIG）等极端情况下才会失败
        bpf_printk("phase_enter: Map update failed for PID, key:%d, phase:%d, ret:%d", key.tid, key.phase, ret);
    } else {
        bpf_printk("phase_enter: Map update OK for PID, key:%d, phase:%d, ret:%d", key.tid, key.phase, ret);
    }

    return 0;
}

static long check(struct bpf_map *map, const void *key, void *value, void *ctx) {
    const struct phase_key* _key = (struct phase_key*)key;
    bpf_printk("check values: tid:%d, phase:%d", _key->tid, _key->phase);

    return 0; // 返回 0 继续遍历，返回 1 停止遍历
}

static __always_inline int phase_exit(__u8 phase) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }



    struct phase_key key = {
        .tid = tid,
        .phase = phase,
    };

    //bpf_for_each_map_elem(&phase_start_map, check, NULL, 0);

    __u64* start_ns = bpf_map_lookup_elem(&phase_start_map, &key);
    if (!start_ns) {
        bpf_printk("phase_exit: start ns not exist in phase_start_map, key:%d, phase:%d", key.tid, key.phase);
        return 0;
    }

    struct phase_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_printk("phase_exit: reserve ringbuf failed, key:%d, phase:%d", key.tid, key.phase);
        bpf_map_delete_elem(&phase_start_map, &key);
        return 0;
    }

    e->type = EVENT_TYPE_PHASE;
    e->start_ns = *start_ns;
    e->end_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->phase = phase;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&phase_start_map, &key);
    return 0;
}

static __always_inline int operator_enter(__u16 op_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    struct operator_depth_key depth_key = {
        .tid = tid,
        .op_id = op_id,
    };
    __u16 depth = 0;
    __u16* current_depth = bpf_map_lookup_elem(&operator_depth_map, &depth_key);
    if (current_depth) {
        depth = *current_depth;
    }

    struct operator_start_key start_key = {
        .tid = tid,
        .op_id = op_id,
        .depth = depth,
    };
    __u64 start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&operator_start_map, &start_key, &start_ns, BPF_ANY);

    __u16 next_depth = depth + 1;
    bpf_map_update_elem(&operator_depth_map, &depth_key, &next_depth, BPF_ANY);

    __u16 stack_depth = get_operator_stack_depth(tid);
    struct active_operator_stack_key stack_key = {
        .tid = tid,
        .stack_depth = stack_depth,
    };
    struct active_operator_stack_value stack_value = {
        .op_id = op_id,
        .op_depth = depth,
    };
    bpf_map_update_elem(&active_operator_stack_map, &stack_key, &stack_value, BPF_ANY);
    set_operator_stack_depth(tid, stack_depth + 1);
    return 0;
}

static __always_inline int operator_exit(__u16 op_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    struct operator_depth_key depth_key = {
        .tid = tid,
        .op_id = op_id,
    };
    __u16* current_depth = bpf_map_lookup_elem(&operator_depth_map, &depth_key);
    if (!current_depth || *current_depth == 0) {
        return 0;
    }

    __u16 depth = *current_depth - 1;
    struct operator_start_key start_key = {
        .tid = tid,
        .op_id = op_id,
        .depth = depth,
    };
    __u64* start_ns = bpf_map_lookup_elem(&operator_start_map, &start_key);
    if (!start_ns) {
        bpf_map_delete_elem(&operator_depth_map, &depth_key);
        return 0;
    }

    struct operator_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&operator_start_map, &start_key);
        if (depth == 0) {
            bpf_map_delete_elem(&operator_depth_map, &depth_key);
        } else {
            bpf_map_update_elem(&operator_depth_map, &depth_key, &depth, BPF_ANY);
        }
        return 0;
    }

    e->type = EVENT_TYPE_OPERATOR;
    e->start_ns = *start_ns;
    e->end_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->op_id = op_id;
    e->depth = depth;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&operator_start_map, &start_key);
    if (depth == 0) {
        bpf_map_delete_elem(&operator_depth_map, &depth_key);
    } else {
        bpf_map_update_elem(&operator_depth_map, &depth_key, &depth, BPF_ANY);
    }

    __u16 stack_depth = get_operator_stack_depth(tid);
    if (stack_depth > 0) {
        struct active_operator_stack_key stack_key = {
            .tid = tid,
            .stack_depth = stack_depth - 1,
        };
        bpf_map_delete_elem(&active_operator_stack_map, &stack_key);
        set_operator_stack_depth(tid, stack_depth - 1);
    }
    return 0;
}

static __always_inline int seq_scan_step_enter(__u8 step_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    struct operator_depth_key seq_key = {
        .tid = tid,
        .op_id = OP_SEQ_SCAN,
    };
    __u16* seq_depth_ptr = bpf_map_lookup_elem(&operator_depth_map, &seq_key);
    if (!seq_depth_ptr || *seq_depth_ptr == 0) {
        return 0;
    }
    __u8 seq_scan_depth = (__u8)(*seq_depth_ptr - 1);

    struct seq_scan_step_depth_key depth_key = {
        .tid = tid,
        .step_id = step_id,
        .seq_scan_depth = seq_scan_depth,
    };
    __u16 depth = 0;
    __u16* current_depth = bpf_map_lookup_elem(&seq_scan_step_depth_map, &depth_key);
    if (current_depth) {
        depth = *current_depth;
    }

    struct seq_scan_step_start_key start_key = {
        .tid = tid,
        .step_id = step_id,
        .seq_scan_depth = seq_scan_depth,
        .depth = depth,
    };
    __u64 start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&seq_scan_step_start_map, &start_key, &start_ns, BPF_ANY);

    __u16 next_depth = depth + 1;
    bpf_map_update_elem(&seq_scan_step_depth_map, &depth_key, &next_depth, BPF_ANY);

    __u16 stack_depth = get_step_stack_depth(tid);
    struct active_step_stack_key stack_key = {
        .tid = tid,
        .stack_depth = stack_depth,
    };
    struct active_step_stack_value stack_value = {
        .step_id = step_id,
        .step_depth = seq_scan_depth,
    };
    bpf_map_update_elem(&active_step_stack_map, &stack_key, &stack_value, BPF_ANY);
    set_step_stack_depth(tid, stack_depth + 1);
    return 0;
}

static __always_inline int seq_scan_step_exit(__u8 step_id) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    struct operator_depth_key seq_key = {
        .tid = tid,
        .op_id = OP_SEQ_SCAN,
    };
    __u16* seq_depth_ptr = bpf_map_lookup_elem(&operator_depth_map, &seq_key);
    if (!seq_depth_ptr || *seq_depth_ptr == 0) {
        return 0;
    }
    __u8 seq_scan_depth = (__u8)(*seq_depth_ptr - 1);

    struct seq_scan_step_depth_key depth_key = {
        .tid = tid,
        .step_id = step_id,
        .seq_scan_depth = seq_scan_depth,
    };
    __u16* current_depth = bpf_map_lookup_elem(&seq_scan_step_depth_map, &depth_key);
    if (!current_depth || *current_depth == 0) {
        return 0;
    }

    __u16 depth = *current_depth - 1;
    struct seq_scan_step_start_key start_key = {
        .tid = tid,
        .step_id = step_id,
        .seq_scan_depth = seq_scan_depth,
        .depth = depth,
    };
    __u64* start_ns = bpf_map_lookup_elem(&seq_scan_step_start_map, &start_key);
    if (!start_ns) {
        bpf_map_delete_elem(&seq_scan_step_depth_map, &depth_key);
        return 0;
    }

    struct seq_scan_step_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&seq_scan_step_start_map, &start_key);
        if (depth == 0) {
            bpf_map_delete_elem(&seq_scan_step_depth_map, &depth_key);
        } else {
            bpf_map_update_elem(&seq_scan_step_depth_map, &depth_key, &depth, BPF_ANY);
        }
        return 0;
    }

    e->type = EVENT_TYPE_SEQ_SCAN_STEP;
    e->start_ns = *start_ns;
    e->end_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->step_id = step_id;
    e->seq_scan_depth = seq_scan_depth;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&seq_scan_step_start_map, &start_key);
    if (depth == 0) {
        bpf_map_delete_elem(&seq_scan_step_depth_map, &depth_key);
    } else {
        bpf_map_update_elem(&seq_scan_step_depth_map, &depth_key, &depth, BPF_ANY);
    }

    __u16 stack_depth = get_step_stack_depth(tid);
    if (stack_depth > 0) {
        struct active_step_stack_key stack_key = {
            .tid = tid,
            .stack_depth = stack_depth - 1,
        };
        bpf_map_delete_elem(&active_step_stack_map, &stack_key);
        set_step_stack_depth(tid, stack_depth - 1);
    }
    return 0;
}

static __always_inline int lwlock_wait_enter(void) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u16 stack_depth = get_operator_stack_depth(tid);
    if (stack_depth == 0) {
        return 0;
    }

    struct lwlock_wait_key key = {
        .tid = tid,
        .depth = stack_depth - 1,
    };
    __u64 start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&lwlock_wait_start_map, &key, &start_ns, BPF_ANY);
    return 0;
}

static __always_inline int lwlock_wait_exit(void) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u16 operator_stack_depth = get_operator_stack_depth(tid);
    if (operator_stack_depth == 0) {
        return 0;
    }

    struct lwlock_wait_key wait_key = {
        .tid = tid,
        .depth = operator_stack_depth - 1,
    };
    __u64* start_ns = bpf_map_lookup_elem(&lwlock_wait_start_map, &wait_key);
    if (!start_ns) {
        return 0;
    }

    struct active_operator_stack_key operator_key = {
        .tid = tid,
        .stack_depth = operator_stack_depth - 1,
    };
    struct active_operator_stack_value* operator_ctx =
        bpf_map_lookup_elem(&active_operator_stack_map, &operator_key);
    if (!operator_ctx) {
        bpf_map_delete_elem(&lwlock_wait_start_map, &wait_key);
        return 0;
    }

    __u8 step_id = 0;
    __u8 step_depth = 0;
    __u16 step_stack_depth = get_step_stack_depth(tid);
    if (step_stack_depth > 0) {
        struct active_step_stack_key step_key = {
            .tid = tid,
            .stack_depth = step_stack_depth - 1,
        };
        struct active_step_stack_value* step_ctx = bpf_map_lookup_elem(&active_step_stack_map, &step_key);
        if (step_ctx) {
            step_id = step_ctx->step_id;
            step_depth = step_ctx->step_depth;
        }
    }

    struct lwlock_wait_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&lwlock_wait_start_map, &wait_key);
        return 0;
    }

    e->type = EVENT_TYPE_LWLOCK_WAIT;
    e->start_ns = *start_ns;
    e->end_ns = bpf_ktime_get_ns();
    e->pid = pid;
    e->tid = tid;
    e->op_id = operator_ctx->op_id;
    e->op_depth = operator_ctx->op_depth;
    e->step_id = step_id;
    e->step_depth = step_depth;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&lwlock_wait_start_map, &wait_key);
    return 0;
}

#define DEFINE_OPERATOR_TRACE(fn_name, op_id) \
SEC("uprobe") \
int trace_##fn_name##_enter(struct pt_regs* ctx) { \
    return operator_enter(op_id); \
} \
SEC("uretprobe") \
int trace_##fn_name##_exit(struct pt_regs* ctx) { \
    return operator_exit(op_id); \
}

#define DEFINE_SEQ_SCAN_STEP_TRACE(fn_name, step_id) \
SEC("uprobe") \
int trace_##fn_name##_enter(struct pt_regs* ctx) { \
    return seq_scan_step_enter(step_id); \
} \
SEC("uretprobe") \
int trace_##fn_name##_exit(struct pt_regs* ctx) { \
    return seq_scan_step_exit(step_id); \
}

#define DEFINE_LWLOCK_WAIT_TRACE(fn_name) \
SEC("uprobe") \
int trace_##fn_name##_enter(struct pt_regs* ctx) { \
    return lwlock_wait_enter(); \
} \
SEC("uretprobe") \
int trace_##fn_name##_exit(struct pt_regs* ctx) { \
    return lwlock_wait_exit(); \
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_sys_enter_recvfrom(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_args args = {
        .buf = (__u64)ctx->args[1],
        .fd = (int)ctx->args[0],
        .direction = IO_DIRECTION_IN,
    };
    bpf_map_update_elem(&read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_sys_enter_read(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_args args = {
        .buf = (__u64)ctx->args[1],
        .fd = (int)ctx->args[0],
        .direction = IO_DIRECTION_IN,
    };
    bpf_map_update_elem(&read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_sys_exit_recvfrom(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    long ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    struct read_args* args = bpf_map_lookup_elem(&read_args_map, &tid);
    if (!args) {
        return 0;
    }

    int len = ret > MAX_DATA ? MAX_DATA : (int)ret;
    struct read_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    e->type = EVENT_TYPE_IO;
    e->pid = pid;
    e->tid = tid;
    e->fd = args->fd;
    e->count = ret;
    e->len = len;
    e->direction = args->direction;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(e->data, len, (const void*)args->buf);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&read_args_map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int trace_sys_exit_read(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    long ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    struct read_args* args = bpf_map_lookup_elem(&read_args_map, &tid);
    if (!args) {
        return 0;
    }

    int len = ret > MAX_DATA ? MAX_DATA : (int)ret;
    struct read_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    e->type = EVENT_TYPE_IO;
    e->pid = pid;
    e->tid = tid;
    e->fd = args->fd;
    e->count = ret;
    e->len = len;
    e->direction = args->direction;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(e->data, len, (const void*)args->buf);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&read_args_map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_args args = {
        .buf = (__u64)ctx->args[1],
        .fd = (int)ctx->args[0],
        .direction = IO_DIRECTION_OUT,
    };
    bpf_map_update_elem(&read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sys_enter_sendto(struct trace_event_raw_sys_enter* ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (!is_target_pid(pid)) {
        return 0;
    }

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    struct read_args args = {
        .buf = (__u64)ctx->args[1],
        .fd = (int)ctx->args[0],
        .direction = IO_DIRECTION_OUT,
    };
    bpf_map_update_elem(&read_args_map, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    long ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    struct read_args* args = bpf_map_lookup_elem(&read_args_map, &tid);
    if (!args) {
        return 0;
    }

    int len = ret > MAX_DATA ? MAX_DATA : (int)ret;
    struct read_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    e->type = EVENT_TYPE_IO;
    e->pid = pid;
    e->tid = tid;
    e->fd = args->fd;
    e->count = ret;
    e->len = len;
    e->direction = args->direction;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(e->data, len, (const void*)args->buf);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&read_args_map, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sys_exit_sendto(struct trace_event_raw_sys_exit* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    if (!is_target_pid(pid)) {
        return 0;
    }

    long ret = ctx->ret;
    if (ret <= 0) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    struct read_args* args = bpf_map_lookup_elem(&read_args_map, &tid);
    if (!args) {
        return 0;
    }

    int len = ret > MAX_DATA ? MAX_DATA : (int)ret;
    struct read_event* e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&read_args_map, &tid);
        return 0;
    }

    e->type = EVENT_TYPE_IO;
    e->pid = pid;
    e->tid = tid;
    e->fd = args->fd;
    e->count = ret;
    e->len = len;
    e->direction = args->direction;
    e->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user(e->data, len, (const void*)args->buf);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&read_args_map, &tid);
    return 0;
}

SEC("uprobe")
int trace_pg_parse_query_enter(struct pt_regs* ctx) {
    return phase_enter(QUERY_PHASE_PARSE);
}

SEC("uretprobe")
int trace_pg_parse_query_exit(struct pt_regs* ctx) {
    return phase_exit(QUERY_PHASE_PARSE);
}

SEC("uprobe")
int trace_pg_analyze_and_rewrite_fixedparams_enter(struct pt_regs* ctx) {
    return phase_enter(QUERY_PHASE_ANALYZE);
}

SEC("uretprobe")
int trace_pg_analyze_and_rewrite_fixedparams_exit(struct pt_regs* ctx) {
    return phase_exit(QUERY_PHASE_ANALYZE);
}

SEC("uprobe")
int trace_pg_analyze_and_rewrite_varparams_enter(struct pt_regs* ctx) {
    return phase_enter(QUERY_PHASE_ANALYZE);
}

SEC("uretprobe")
int trace_pg_analyze_and_rewrite_varparams_exit(struct pt_regs* ctx) {
    return phase_exit(QUERY_PHASE_ANALYZE);
}

SEC("uprobe")
int trace_pg_analyze_and_rewrite_withcb_enter(struct pt_regs* ctx) {
    return phase_enter(QUERY_PHASE_ANALYZE);
}

SEC("uretprobe")
int trace_pg_analyze_and_rewrite_withcb_exit(struct pt_regs* ctx) {
    return phase_exit(QUERY_PHASE_ANALYZE);
}

SEC("uprobe")
int trace_pg_plan_queries_enter(struct pt_regs* ctx) {
    return phase_enter(QUERY_PHASE_PLAN);
}

SEC("uretprobe")
int trace_pg_plan_queries_exit(struct pt_regs* ctx) {
    return phase_exit(QUERY_PHASE_PLAN);
}

SEC("uprobe")
int trace_PortalRun_enter(struct pt_regs* ctx) {
    return phase_enter(QUERY_PHASE_EXECUTE);
}

SEC("uretprobe")
int trace_PortalRun_exit(struct pt_regs* ctx) {
    return phase_exit(QUERY_PHASE_EXECUTE);
}

DEFINE_OPERATOR_TRACE(ExecResult, OP_RESULT)
DEFINE_OPERATOR_TRACE(ExecSeqScan, OP_SEQ_SCAN)
DEFINE_OPERATOR_TRACE(ExecIndexScan, OP_INDEX_SCAN)
DEFINE_OPERATOR_TRACE(ExecIndexOnlyScan, OP_INDEX_ONLY_SCAN)
DEFINE_OPERATOR_TRACE(ExecBitmapIndexScan, OP_BITMAP_INDEX_SCAN)
DEFINE_OPERATOR_TRACE(ExecBitmapHeapScan, OP_BITMAP_HEAP_SCAN)
DEFINE_OPERATOR_TRACE(ExecTidScan, OP_TID_SCAN)
DEFINE_OPERATOR_TRACE(ExecSubqueryScan, OP_SUBQUERY_SCAN)
DEFINE_OPERATOR_TRACE(ExecFunctionScan, OP_FUNCTION_SCAN)
DEFINE_OPERATOR_TRACE(ExecValuesScan, OP_VALUES_SCAN)
DEFINE_OPERATOR_TRACE(ExecCteScan, OP_CTE_SCAN)
DEFINE_OPERATOR_TRACE(ExecWorkTableScan, OP_WORKTABLE_SCAN)
DEFINE_OPERATOR_TRACE(ExecNestLoop, OP_NEST_LOOP)
DEFINE_OPERATOR_TRACE(ExecMergeJoin, OP_MERGE_JOIN)
DEFINE_OPERATOR_TRACE(ExecHashJoin, OP_HASH_JOIN)
DEFINE_OPERATOR_TRACE(ExecMaterial, OP_MATERIALIZE)
DEFINE_OPERATOR_TRACE(ExecSort, OP_SORT)
DEFINE_OPERATOR_TRACE(ExecGroup, OP_GROUP)
DEFINE_OPERATOR_TRACE(ExecAgg, OP_AGGREGATE)
DEFINE_OPERATOR_TRACE(ExecWindowAgg, OP_WINDOW_AGG)
DEFINE_OPERATOR_TRACE(ExecUnique, OP_UNIQUE)
DEFINE_OPERATOR_TRACE(ExecAppend, OP_APPEND)
DEFINE_OPERATOR_TRACE(ExecMergeAppend, OP_MERGE_APPEND)
DEFINE_OPERATOR_TRACE(ExecLimit, OP_LIMIT)
DEFINE_OPERATOR_TRACE(ExecLockRows, OP_LOCK_ROWS)
DEFINE_OPERATOR_TRACE(ExecModifyTable, OP_MODIFY_TABLE)
DEFINE_OPERATOR_TRACE(ExecHash, OP_HASH)
DEFINE_OPERATOR_TRACE(ExecGather, OP_GATHER)
DEFINE_OPERATOR_TRACE(ExecGatherMerge, OP_GATHER_MERGE)
DEFINE_OPERATOR_TRACE(ExecSetOp, OP_SET_OP)
DEFINE_OPERATOR_TRACE(ExecProjectSet, OP_PROJECT_SET)
DEFINE_OPERATOR_TRACE(ExecMemoize, OP_MEMOIZE)
DEFINE_OPERATOR_TRACE(MultiExecBitmapAnd, OP_BITMAP_AND)
DEFINE_OPERATOR_TRACE(MultiExecBitmapOr, OP_BITMAP_OR)
DEFINE_SEQ_SCAN_STEP_TRACE(ExecScan, SEQ_SCAN_STEP_EXEC_SCAN)
DEFINE_LWLOCK_WAIT_TRACE(LWLockQueueSelf)
