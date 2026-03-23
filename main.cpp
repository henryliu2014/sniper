#include <iostream>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <string>
#include <vector>
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

static std::vector<pid_t> find_postgres_pids() {
    std::vector<pid_t> pids;
    DIR* dir = opendir("/proc");
    if (!dir) {
        return pids;
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

        pids.push_back(pid);
    }

    closedir(dir);
    std::sort(pids.begin(), pids.end());
    pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
    return pids;
}

// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
int main() {
    std::vector<pid_t> pids = find_postgres_pids();
    if (pids.empty()) {
        std::cerr << "No running postgres processes found\n";
        return 1;
    }

    int duration_sec = 10;
    if (const char* d = std::getenv("PROBE_DURATION_SEC")) {
        duration_sec = std::atoi(d);
        if (duration_sec <= 0) {
            duration_sec = 10;
        }
    }

    return pg_probe(pids, duration_sec);
}
