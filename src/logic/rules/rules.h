#pragma once

#include <vector>
#include <map>
#include <string>

enum RuleType { DENY_PATH_ACCESS = 0, DENY_ALWAYS, ALLOW_WITH_LOG };

struct Rule {
    int rule_id;
    RuleType type;
    std::string path;
};

struct RuleInfo {
    std::vector<int> pids;

    std::vector<int> vec_syscalls;
};