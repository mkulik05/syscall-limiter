#pragma once

#include <vector>
#include <unordered_map>
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
    
        void stopRunning();

        void ruleInit(pid_t pid);

        pid_t pid;
        
    private:
        void handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd);

        int addRuleUnsync(pid_t pid, Rule rule, std::vector<int> syscalls); 
        void deleteRuleUnsync(int rule_id);

        int curr_syscalls_n;
        pid_t starter_pid;
        
        // For sync access to data (between supervisor and rule editing thread)
        sem_t* semaphore;

        // { syscall_n: handler_pnt}
        std::unordered_map<int, MapHandler> map_handlers;
                // For generating rules id 
        std::mt19937 rnd_gen;                      
        std::uniform_int_distribution<> rnd_dis;
    
        bool runnable;

        // { pid: {syscall_n: [rule1, rule2] .. } .. }
        std::unordered_map<int, std::unordered_map<int, std::vector<Rule>>> map_all_rules;

        // { rule_id : info}
        std::unordered_map<int, RuleInfo> map_rules_info;

        // {pid: [rule_id1, rule_id2] ..}
        // Used for speeding up duplication of data in map_rules_ids
        std::unordered_map<int, std::vector<int>> map_pid_rules;

        // {parent_pid1: [child_pid1, child_pid2] ..}
        std::unordered_map<int, std::vector<int>> map_pids_tree;
        void PIDTreeAddRule(std::vector<int> *res, pid_t pid, Rule rule, std::vector<int> syscalls);
};