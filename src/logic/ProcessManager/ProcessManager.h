#pragma once

#include <fcntl.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>

#include "../Supervisor/Manager/Supervisor.h"
#include "../SocketBridge/SocketBridge.h"
#include "../rules/rules.h"

class ProcessManager {
    public:
        ProcessManager();
        virtual ~ProcessManager();
        
        // Adds process in suspended state, returns handle to it 
        pid_t addProcess(std::string cmd, std::string log_path);

        // Used to start process (it is added in suspended state)
        void startProcess(pid_t pid);

        // Terminate process
        void stopProcess(pid_t pid);

        // Add new rule to process
        int addRule(pid_t pid, Rule rule, std::vector<int> syscalls); 

        // Remove some old rules and add a group of new ones
        std::vector<int> updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules);

        // Sets memory and time limit for process 
        int setMemTime(pid_t pid, std::string maxMem, int maxTime);

        // Checks whether process is still running
        bool is_process_running(pid_t pid);

        // Pids of started processes
        std::vector<pid_t> startedPIDs;
        
        Supervisor* supervisor;

    private:

        void downgrade_privileges();
        
        SocketBridge* fd_bridge;
        SocketBridge* task_bridge;
        SocketBridge* started_pids_bridge;

        pid_t process_starter_pid;

        void process_starter();
        void start_supervisor(pid_t starter_pid);
        std::thread thread_supervisor, thread_process_starter;

        bool runnable;

        std::unordered_map<int, std::string> map_cgroup;
        std::string cgroup_path;

        
};