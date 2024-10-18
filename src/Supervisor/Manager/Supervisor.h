class Supervisor {
    public:
        Supervisor(pid_t starter_pid);
        void run(int notifyFd);
        // void addRule();
        // void deleteRule();
        // void updateRule();

        pid_t pid;
    
    private:
        pid_t starter_pid;
};