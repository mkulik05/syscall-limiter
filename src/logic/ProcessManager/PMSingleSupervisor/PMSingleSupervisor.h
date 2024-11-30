#pragma once

#include <fcntl.h>
#include <vector>
#include <thread>
#include "../../Supervisor/Manager/ManyProcessesSP/ManyProcessesSP.h"
#include "../PM/ProcessManager.h"

class PMSingleSupervisor: public ProcessManager {
    public:
        PMSingleSupervisor();
        ~PMSingleSupervisor();
        
        int addProcess(std::string cmd, std::string log_path) override;
        void startProcess(pid_t pid) override;
        void stopProcess(pid_t pid) override;

        int addRule(pid_t pid, Rule rule, std::vector<int> syscalls) override; 

        std::vector<int> updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) override;
    
    protected: 
        void start_process(Strings & task, int & stdoutFd, int & stderrFd) override;
        void prepare_starter() override;

    private:
        ManyProcessesSP* supervisor;

        void start_supervisor(pid_t starter_pid);
        std::thread thread_supervisor, thread_process_starter;

        bool runnable;
};