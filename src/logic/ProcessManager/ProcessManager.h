#pragma once

#include <fcntl.h>
#include <string>
#include <vector>
#include <thread>
#include "../SocketBridge/SocketBridge.h"
#include "../Supervisor/Manager/Supervisor.h"

class ProcessManager {
    public:
        ProcessManager();
        ~ProcessManager();
        pid_t addProcess(std::string cmd, std::string log_path);
        void startProcess(pid_t pid);
        int setMemTime(pid_t pid, std::string maxMem, int maxTime);
        void stopProcess(pid_t pid);

        std::vector<pid_t> startedPIDs;
        Supervisor* supervisor;

        bool is_process_running(pid_t pid);
        
    private:
        void broadcast_signal(int sig_n);
        void process_starter();
        void start_supervisor(pid_t starter_pid);

        pid_t process_starter_pid;
        
        SocketBridge* fd_bridge;
        SocketBridge* task_bridge;
        SocketBridge* started_pids_bridge;

        std::thread thread_supervisor, thread_process_starter;

        std::unordered_map<int, std::string> map_cgroup;
        std::string cgroup_path;
};