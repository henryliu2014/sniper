#pragma once

#include <sys/types.h>
#include <vector>

// Attach eBPF probes for Postgres socket traffic and phase timing.
// Returns 0 on success, non-zero on failure.
int pg_probe(const std::vector<pid_t>& postgres_pids, int duration_sec);
