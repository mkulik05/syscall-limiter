#include <fcntl.h>
#include <string>

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
        void process_starter(int sockPair[2]);
        void start_supervisor(int sockPair[2], pid_t starter_pid);

        pid_t process_starter_pid;

        Supervisor* supervisor;
        pid_t supervisor_pid;

        // To distinguish msgs
        long start_process_msg_type; 
};