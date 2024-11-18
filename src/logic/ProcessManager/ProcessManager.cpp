#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <map>
#include <vector>
#include <iostream>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <fstream>
#include <sys/types.h>
#include <pwd.h>
#include <sys/resource.h>

#include "../Supervisor/Manager/Supervisor.h"
#include "../seccomp/seccomp.h"
#include "../ProcessManager/ProcessManager.h"
#include "../Logger/Logger.h" 


extern const char *program_pathname;

std::string getCgroupMountPoint();

ProcessManager::~ProcessManager() {
    broadcast_signal(SIGKILL);
    this->thread_supervisor.~thread();
    delete this->started_pids_bridge;
    delete this->fd_bridge;
}

ProcessManager::ProcessManager()
{   
    Logger::getInstance().setVerbosity(Logger::Verbosity::DEBUG);
    this->cgroup_path = getCgroupMountPoint();
    this->map_cgroup = {};
    this->startedPIDs = std::vector<pid_t>();
    this->fd_bridge = new SocketBridge();
    this->started_pids_bridge = new SocketBridge();


    pid_t targetPid = fork();

    if (targetPid == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (targetPid > 0) {
        this->supervisor = new Supervisor(targetPid);
        Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter pid: %d", targetPid);
        this->thread_supervisor = std::thread([this, targetPid]() {
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "Before starting supervisor in sep thread");
            this->start_supervisor(targetPid);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "After starting supervisor in sep thread");
        });

        this->process_starter_pid = targetPid;
        return;
    } 
       
    this->process_starter();
    exit(EXIT_SUCCESS);
}

std::string getCgroupMountPoint() {
    std::ifstream mountsFile("/proc/mounts");
    if (!mountsFile.is_open()) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Error opening /proc/mounts");
        return "";
    }

    std::string line;
    while (std::getline(mountsFile, line)) {
        std::istringstream iss(line);
        std::string device, mountPoint, fstype, options;

        if (iss >> device >> mountPoint >> fstype >> options) {
            if (mountPoint.find("cgroup") != std::string::npos) {
                mountsFile.close();
                return mountPoint;
            }
        }
    }

    mountsFile.close();
    return "";
}

int writeToFile(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (file.is_open()) {
        file << content;
        file.close();
        return 0;
    } else {
        return -1;
    }
}


int ProcessManager::setMemTime(pid_t pid, std::string maxMem, int maxTime) {
    Logger::getInstance().log(Logger::Verbosity::DEBUG, "Updating maxMem and maxTime");
    
    Logger::getInstance().log(Logger::Verbosity::DEBUG, "euid is %d", getuid());

    
    if (cgroup_path == "") {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "cgroup_path is empty, skipping: %s", strerror(errno));
        return -1;
    }
    
    std::string path;
    if (this->map_cgroup.count(pid) == 0) {
        path = cgroup_path + "/map_control-" + std::to_string(pid) + "-" + std::to_string(std::rand());
        if(mkdir(path.c_str(), 0777) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to create folder: %s", strerror(errno));
            return -1;
        }
        if(writeToFile(path + "/cgroup.procs", std::to_string(pid)) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to set cgroup pid: %s", strerror(errno));
            return -1;
        }
        this->map_cgroup[pid] = path;
    } else {
        path = map_cgroup[pid];
    }
    if(writeToFile(path + "/memory.max", maxMem) == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to set cgroup memory.max: %s", strerror(errno));
        return -1;
    }

    if(writeToFile(path + "/memory.swap.max", "0") == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to set cgroup memory.swap.max: %s", strerror(errno));
        return -1;
    }

    return 0;
}

#include <fstream>
#include <sstream>
#include <string>

bool is_process_zombie(pid_t pid) {
    std::ifstream stat_file("/proc/" + std::to_string(pid) + "/stat");
    std::string line;

    if (!stat_file.is_open()) {
        return false;
    }

    if (std::getline(stat_file, line)) {
        std::istringstream iss(line);
        std::string token;
        int field_index = 0;

        while (iss >> token) {
            if (field_index == 2) { 
                return (token == "Z"); 
            }
            field_index++;
        }
    }
    return false;
}

void ProcessManager::startProcess(pid_t pid) {    
    usleep(100000); // 100ms

    Logger::getInstance().log(Logger::Verbosity::INFO, "SIGCONT sender: Starting process with PID: %d", pid);
    kill(pid, SIGCONT);
}

void ProcessManager::broadcast_signal(int sygn_n) {
    kill(this->process_starter_pid, sygn_n);
    for (int i = 0; i < this->startedPIDs.size(); i++) {
        kill(this->startedPIDs[i], sygn_n);
    }
    kill(this->supervisor->pid, sygn_n);
}


pid_t ProcessManager::addProcess(std::string cmd) {
    key_t key = ftok(program_pathname, START_PROCESS_IPC_VALUE);
    if (key == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "ftok error: %s", strerror(errno));
        return -1;
    }
    
    int msgid = msgget(key, 0666 | IPC_CREAT);

    if (msgid == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "msgget error: %s", strerror(errno));
        return -1;
    }
    struct msg_buffer message;
    message.msg_type = 1;
    strncpy(message.msg_text, cmd.c_str(), sizeof(message.msg_text));
    // this->start_process_msg_type += 1;
    if (msgsnd(msgid, &message, cmd.length(), 0) == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "msgsnd error: %s", strerror(errno));
        return -1;
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Adding process: before receiving new proc fd");
    int process_pid = this->started_pids_bridge->recv_int();
    Logger::getInstance().log(Logger::Verbosity::INFO, "FD received: %d", process_pid);
    this->startedPIDs.push_back(process_pid);
    return process_pid;
}

void ProcessManager::start_supervisor(pid_t starter_pid) {
    Logger::getInstance().log(Logger::Verbosity::INFO, "%d ", 44);
    int notifyFd = this->fd_bridge->recv_fd();
    if (notifyFd == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "recv_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "%d", 47);
    this->fd_bridge;


    this->supervisor->run(notifyFd);
}

bool ProcessManager::is_process_running(pid_t pid) {
    return (kill(pid, 0) == 0) && (!is_process_zombie(pid));
}

void ProcessManager::process_starter() {

    struct stat info;
    stat(program_pathname, &info);
    struct passwd *pw = getpwuid(info.st_uid);  
    if (setregid(info.st_gid, info.st_gid) != 0) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to drop priviledges (setregid)");
        err(EXIT_FAILURE, "Failed to drop priviledges (setregid)");
    }

    if (setreuid(info.st_uid, info.st_uid) != 0) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to drop priviledges (setreuid)");
        err(EXIT_FAILURE, "Failed to drop priviledges (setreuid)");
    } 
    
    if (pw->pw_dir) {
        setenv("HOME", pw->pw_dir, 1);
    }

    Logger::getInstance().log(Logger::Verbosity::DEBUG, "User euid: %d", geteuid());

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Process starter prctl error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "ftok file key: %s", program_pathname);
    key_t key = ftok(program_pathname, START_PROCESS_IPC_VALUE);
    if (key == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Process starter ftok error: %s", strerror(errno));
        return;
    }
    int msgid = msgget(key, 0666 | IPC_CREAT);
    if (msgid == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Process starter msgget error: %s", strerror(errno));
        return;
    }

    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: starting seccomp filter installation");
    int notifyFd = installNotifyFilter();

    if (this->fd_bridge->send_fd(notifyFd) == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "send_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: sent fd");

    // if (close(notifyFd) == -1) {
    //     Logger::getInstance().log(Logger::Verbosity::ERROR, "Process starter close-fd error: %s", strerror(errno));
    //     exit(EXIT_FAILURE);
    // }

    struct msg_buffer message;

    for (;;) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: waiting for command to start");
        size_t n = msgrcv(msgid, &message, sizeof(message.msg_text), 1, 0);
        Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: got command");
        if (n == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Process starter: msgrcv error: %s", strerror(errno));
            return;
        }
        std::string command = message.msg_text;

        Logger::getInstance().log(Logger::Verbosity::INFO, "Command: '%s'", command.substr(0, n).c_str());
        pid_t targetPid = fork();
        if (targetPid == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s", strerror(errno));
        }

        if (targetPid != 0) {   
            if (this->started_pids_bridge->send_int(targetPid) == -1) {
                Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to send started process descriptor: %s", strerror(errno));
            }
            Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: process started with PID: %d", targetPid);
        } else {
            // Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process before stopping");
            kill(getpid(), SIGSTOP);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process resumed");
            execl("/bin/sh", "sh", "-c", command.substr(0, n).c_str(), (char *) NULL);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process finished");
            exit(EXIT_SUCCESS);
        }
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: finished execution");
}