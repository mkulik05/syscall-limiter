#pragma once

#include <vector>
#include <unordered_map>
#include <random>
#include <semaphore.h>

#include "../../handlers/handlers.h"

class Supervisor {
    public:
        Supervisor(pid_t starter_pid);
        void run(int notifyFd);
        int addRule(pid_t pid, Rule rule, std::vector<int> syscalls); // returns rule id
        void deleteRule(int rule_id);

        virtual int updateRule(pid_t pid, int rule_id, Rule rule) = 0; // returns new rule id

        std::vector<int> updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules);
    
        void stopRunning();

    protected:
        virtual void handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd) = 0;
        virtual int addRuleUnsync(pid_t pid, Rule rule, std::vector<int> syscalls) = 0; 
        virtual void deleteRuleUnsync(int rule_id) = 0;

        pid_t starter_pid;
        
        // For sync access to data (between supervisor and rule editing thread)
        sem_t* semaphore;

        // { syscall_n: handler_pnt}
        std::unordered_map<int, MapHandler> map_handlers;
                // For generating rules id 
        std::mt19937 rnd_gen;                      
        std::uniform_int_distribution<> rnd_dis;
    
    private:
        bool runnable;
};