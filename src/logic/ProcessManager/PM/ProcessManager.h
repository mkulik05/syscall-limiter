#pragma once

#include <fcntl.h>
#include <string>
#include <vector>
#include <unordered_map>

#include "../../SocketBridge/SocketBridge.h"
#include "../../rules/rules.h"

class ProcessManager {
    public:
        ProcessManager();
        virtual ~ProcessManager();
        
        // Adds process in suspended state, returns handle to it 
        virtual int addProcess(std::string cmd, std::string log_path);

        // Used to start process (it is added in suspended state)
        virtual void startProcess(int id) = 0;

        // Terminate process
        virtual void stopProcess(int id) = 0;

        // Add new rule to process
        virtual int addRule(int id, Rule rule, std::vector<int> syscalls) = 0; 

        // Remove some old rules and add a group of new ones
        virtual std::vector<int> updateRules(int id, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) = 0;

        // Sets memory and time limit for process 
        virtual int setMemTime(pid_t pid, std::string maxMem, int maxTime);

        // Checks whether process is still running
        virtual bool is_process_running(pid_t pid);

        // Pids of started processes
        std::vector<int> startedIDs;
        
        void process_starter();
        
    protected:

        void downgrade_privileges();
        
        SocketBridge* fd_bridge;
        SocketBridge* started_pids_bridge;
        SocketBridge* task_bridge;

        pid_t process_starter_pid;

        virtual void start_process(Strings & task, int & stdoutFd, int & stderrFd) = 0;

        virtual void prepare_starter();
      private:
        bool runnable;
        std::unordered_map<int, std::string> map_cgroup;
        std::string cgroup_path;
};