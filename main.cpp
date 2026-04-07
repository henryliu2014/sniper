#include <iostream>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <cctype>
#include <algorithm>
#include "pg_probe.h"

static bool is_numeric(const char* s) {
    if (!s || !*s) {
        return false;
    }
    for (const char* p = s; *p; ++p) {
        if (!std::isdigit(static_cast<unsigned char>(*p))) {
            return false;
        }
    }
    return true;
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f) {
        return {};
    }
    std::string data((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    return data;
}

static pid_t read_ppid(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/status");
    if (!f) {
        return -1;
    }

    std::string key;
    while (f >> key) {
        if (key == "PPid:") {
            pid_t ppid = -1;
            f >> ppid;
            return ppid;
        }
        std::string value;
        std::getline(f, value);
    }

    return -1;
}

static std::vector<pid_t> find_postmaster_pids() {
    struct postgres_process {
        pid_t pid;
        pid_t ppid;
    };

    std::vector<postgres_process> postgres_processes;
    std::unordered_set<pid_t> postgres_pids;
    DIR* dir = opendir("/proc");
    if (!dir) {
        return {};
    }

    dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        if (!is_numeric(ent->d_name)) {
            continue;
        }
        pid_t pid = static_cast<pid_t>(std::atoi(ent->d_name));
        if (pid <= 0) {
            continue;
        }

        std::string comm = read_file(std::string("/proc/") + ent->d_name + "/comm");
        if (comm.empty()) {
            continue;
        }
        if (!comm.empty() && comm.back() == '\n') {
            comm.pop_back();
        }

        if (comm != "postgres") {
            continue;
        }

        std::string cmdline = read_file(std::string("/proc/") + ent->d_name + "/cmdline");
        if (cmdline.empty()) {
            continue;
        }

        postgres_processes.push_back({
            .pid = pid,
            .ppid = read_ppid(pid),
        });
        postgres_pids.insert(pid);
    }

    closedir(dir);

    std::vector<pid_t> postmasters;
    for (const auto& process : postgres_processes) {
        if (process.ppid > 0 && postgres_pids.contains(process.ppid)) {
            continue;
        }
        postmasters.push_back(process.pid);
    }

    std::sort(postmasters.begin(), postmasters.end());
    postmasters.erase(std::unique(postmasters.begin(), postmasters.end()), postmasters.end());
    return postmasters;
}

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
int main() {
    std::vector<pid_t> pids = find_postmaster_pids();
    if (pids.empty()) {
        std::cerr << "No running postgres postmaster processes found\n";
        return 1;
    }

    int duration_sec = 200;
    if (const char* d = std::getenv("PROBE_DURATION_SEC")) {
        duration_sec = std::atoi(d);
        if (duration_sec <= 0) {
            duration_sec = 100;
        }
    }

    return pg_probe(pids, duration_sec);
}
