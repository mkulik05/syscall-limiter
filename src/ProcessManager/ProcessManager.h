#include <fcntl.h>
#include <string>
#include <vector>
#include "../SocketBridge/SocketBridge.h"

#define MSG_SIZE 512
#define START_PROCESS_IPC_VALUE 'B'
#define START_PROCESS_RETURN_PID 78

// Used for sending execution commands to process_starter
struct msg_buffer {
    long msg_type; 
    char msg_text[MSG_SIZE]; 
};

class ProcessManager {
    public:
        ProcessManager();
        pid_t startProcess(std::string cmd);
        
    private:
        // TODO: add started process pid returning
        void process_starter();
        void start_supervisor(pid_t starter_pid);

        pid_t process_starter_pid;

        Supervisor* supervisor;
        
        SocketBridge* fd_bridge;
        SocketBridge* started_pids_bridge;

        // To distinguish msgs
        long start_process_msg_type; 

        std::vector<pid_t> startedPIDs;
};