#pragma once

#include <set>
#include <vector>
#include <map>
#include <unordered_map>
#include <string>
#include <random>
#include <semaphore.h>

#include "../handlers/handlers.h"

class Supervisor {
    public:
        Supervisor(pid_t starter_pid);
        void run(int notifyFd);
        int addRule(pid_t pid, Rule rule, std::vector<int> syscalls); // returns rule id
        void deleteRule(int rule_id);
        int updateRule(pid_t pid, int rule_id, Rule rule); // returns new rule id

        std::vector<int> updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules);

        pid_t pid;
    private:

        int addRuleUnsync(pid_t pid, Rule rule, std::vector<int> syscalls); 
        void deleteRuleUnsync(int rule_id);
        void handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd);

        pid_t starter_pid;

        // { pid: {syscall_n: [rule1, rule2] .. } .. }
        std::unordered_map<int, std::map<int, std::vector<Rule>>> map_all_rules;

        // { rule_id : info}
        std::unordered_map<int, RuleInfo> map_rules_info;

        // {pid: [rule_id1, rule_id2] ..}
        // Used for speeding up duplication of data in map_rules_ids
        std::unordered_map<int, std::vector<int>> map_pid_rules;

        // For generating rules id 
        std::mt19937 rnd_gen;                      
        std::uniform_int_distribution<> rnd_dis;

        // For sync access to map_all_rules and map_rules_ids
        sem_t* semaphore;

        // { syscall_n: handler_pnt}
        std::unordered_map<int, MapHandler> map_handlers;
};