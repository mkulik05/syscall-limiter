#pragma once

#include <fcntl.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>
#include "../../Supervisor/Manager/OneProcessSP/OneProcessSP.h"
#include "../PM/ProcessManager.h"

class PMManySupervisors: public ProcessManager {
    public:
        PMManySupervisors();
        ~PMManySupervisors();

        int addProcess(std::string cmd, std::string log_path) override;
        void startProcess(int id) override;
        void stopProcess(int id) override;

        int addRule(int id, Rule rule, std::vector<int> syscalls) override; 

        std::vector<int> updateRules(int id, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) override;
    
    protected:
        void start_process(Strings & task, int & stdoutFd, int & stderrFd) override;
    
    private:
        std::vector<OneProcessSP*> supervisors;
        sem_t* sem_supervisors;

        std::vector<std::thread> thread_processes;
        std::vector<std::thread> thread_supervisors;

        std::thread thread_process_spawner;
        
        sem_t* sem_threads;
        bool runnable;

        std::unordered_map<pid_t, int> map_pid_arr_i;
};