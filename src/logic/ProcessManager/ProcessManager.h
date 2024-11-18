#pragma once

#include <fcntl.h>
#include <string>
#include <vector>
#include <thread>
#include "../SocketBridge/SocketBridge.h"
#include "../Supervisor/Manager/Supervisor.h"

#define MSG_SIZE 512
#define START_PROCESS_IPC_VALUE 'C'
#define START_PROCESS_RETURN_PID 78

// Used for sending execution commands to process_starter
struct msg_buffer {
    long msg_type; 
    char msg_text[MSG_SIZE]; 
};

class ProcessManager {
    public:
        ProcessManager();
        ~ProcessManager();
        void broadcast_signal(int sig_n);
        pid_t addProcess(std::string cmd);
        void startProcess(pid_t pid);
        int setMemTime(pid_t pid, std::string maxMem, int maxTime);

        std::vector<pid_t> startedPIDs;
        Supervisor* supervisor;
        bool is_process_running(pid_t pid);
        
    private:
        void process_starter();
        void start_supervisor(pid_t starter_pid);

        pid_t process_starter_pid;
        
        SocketBridge* fd_bridge;
        SocketBridge* started_pids_bridge;

        std::thread thread_supervisor, thread_process_starter;

        std::unordered_map<int, std::string> map_cgroup;
        std::string cgroup_path;
};