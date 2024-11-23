#pragma once

#include <fcntl.h>
#include <string>
#include <vector>
#include <thread>
#include "../../SocketBridge/SocketBridge.h"
#include "../../Supervisor/Manager/Supervisor.h"
#include "../PM/ProcessManager.h"

class PMSingleSupervisor: public ProcessManager {
    public:
        PMSingleSupervisor();
        ~PMSingleSupervisor();

        pid_t addProcess(std::string cmd, std::string log_path) override;
        void startProcess(pid_t pid) override;
        void stopProcess(pid_t pid) override;

        int addRule(pid_t pid, Rule rule, std::vector<int> syscalls) override; 

        std::vector<int> updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) override;

        Supervisor* supervisor;
        
    private:

        pid_t process_starter_pid;

        void process_starter();
        void start_supervisor(pid_t starter_pid);
        std::thread thread_supervisor, thread_process_starter;
};