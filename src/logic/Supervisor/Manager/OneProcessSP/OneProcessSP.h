#pragma once

#include <vector>
#include <map>
#include <unordered_map>
#include <semaphore.h>

#include "../Supervisor/Supervisor.h"

class OneProcessSP: public Supervisor {
    public:
        OneProcessSP(pid_t starter_pid);
        int updateRule(pid_t pid, int rule_id, Rule rule) override;
        pid_t pid;
        
        void ruleInit(pid_t pid);

    protected:
        void handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd) override;
        int addRuleUnsync(pid_t pid, Rule rule, std::vector<int> syscalls) override; 
        void deleteRuleUnsync(int rule_id) override;

    private:

        // { pid: {syscall_n: [rule1, rule2] .. } .. }
        std::unordered_map<int, std::map<int, std::vector<Rule>>> map_all_rules;

        // { rule_id : info}
        std::unordered_map<int, RuleInfo> map_rules_info;

        // {pid: [rule_id1, rule_id2] ..}
        // Used for speeding up duplication of data in map_rules_ids
        std::unordered_map<int, std::vector<int>> map_pid_rules;

};