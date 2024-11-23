#pragma once

#include <fcntl.h>
#include <string>
#include <vector>
#include <thread>
#include "../../SocketBridge/SocketBridge.h"
#include "../../Supervisor/Manager/Supervisor.h"

class ProcessManager {
    public:
        ProcessManager();
        virtual ~ProcessManager();
        
        // Adds process in suspended state, returns handle to it 
        virtual pid_t addProcess(std::string cmd, std::string log_path) = 0;

        // Used to start process (it is added in suspended state)
        virtual void startProcess(pid_t pid) = 0;

        // Terminate process
        virtual void stopProcess(pid_t pid) = 0;

        // Add new rule to process
        virtual int addRule(pid_t pid, Rule rule, std::vector<int> syscalls) = 0; 

        // Remove some old rules and add a group of new ones
        virtual std::vector<int> updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) = 0;

        // Sets memory and time limit for process 
        int setMemTime(pid_t pid, std::string maxMem, int maxTime);

        // Checks whether process is still running
        bool is_process_running(pid_t pid);

        // Pids of started processes
        std::vector<pid_t> startedPIDs;
        
    protected:

        void downgrade_privileges();
        
        SocketBridge* fd_bridge;
        SocketBridge* task_bridge;
        SocketBridge* started_pids_bridge;

    private:

        std::unordered_map<int, std::string> map_cgroup;
        std::string cgroup_path;
};