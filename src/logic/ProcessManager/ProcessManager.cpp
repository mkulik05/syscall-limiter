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
#include <vector>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <fstream>
#include <sys/types.h>
#include <pwd.h>
#include <sys/resource.h>
#include <fstream>
#include <sstream>

#include "../seccomp/seccomp.h"
#include "../Logger/Logger.h" 
#include "ProcessManager.h"


extern const char *program_pathname;

std::string getCgroupMountPoint();


ProcessManager::~ProcessManager() {
    delete this->started_pids_bridge;
    delete this->fd_bridge;
    for (const auto& pair : map_cgroup) {
        int res = rmdir(pair.second.c_str());
        if (res != 0) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to remove cgroup: %s", strerror(errno));
        } 
    }
    
    kill(this->process_starter_pid, SIGTERM);
    for (int i = 0; i < this->startedPIDs.size(); i++) {
        kill(this->startedPIDs[i], SIGTERM);
    }
    this->supervisor->stopRunning();
    pthread_kill(this->thread_supervisor.native_handle(), SIGINT);
    this->thread_supervisor.join();

    runnable = false;
    pthread_kill(this->thread_process_starter.native_handle(), SIGINT);
    this->thread_process_starter.join();
}

ProcessManager::ProcessManager()
{   
    Logger::getInstance().setVerbosity(Logger::Verbosity::DEBUG);
    this->cgroup_path = getCgroupMountPoint();
    this->map_cgroup = {};
    this->startedPIDs = std::vector<pid_t>();
    this->fd_bridge = new SocketBridge();
    this->task_bridge = new SocketBridge();
    this->started_pids_bridge = new SocketBridge();
    
    runnable = true;
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

        process_starter_pid = targetPid;
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

    int totalCpuTime = 100000;
    int cpuLimit = (maxTime * totalCpuTime) / 100; 

    std::string cpuLimitStr = std::to_string(cpuLimit) + " 100000";
    if(writeToFile(path + "/cpu.max", cpuLimitStr) == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to set cgroup cpu.max: %s", strerror(errno));
        return -1;
    }

    return 0;
}

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

bool ProcessManager::is_process_running(pid_t pid) {
    return (kill(pid, 0) == 0) && (!is_process_zombie(pid));
}

void ProcessManager::downgrade_privileges() {
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

}



void ProcessManager::startProcess(pid_t pid) {    
    usleep(100000); // 100ms

    Logger::getInstance().log(Logger::Verbosity::INFO, "SIGCONT sender: Starting process with PID: %d", pid);
    kill(pid, SIGCONT);
}


void ProcessManager::stopProcess(pid_t pid) {
    kill(pid, SIGTERM);
}


pid_t ProcessManager::addProcess(std::string cmd, std::string log_path) {
    Strings buf = {cmd, log_path};
    int r = task_bridge->send_strings(buf);
    if (r != 0) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to send task: %s", strerror(errno));
        return -1;
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Adding process: before receiving new proc fd");
    int process_pid = started_pids_bridge->recv_int();
    Logger::getInstance().log(Logger::Verbosity::INFO, "process PID received: %d", process_pid);
    this->startedPIDs.push_back(process_pid);

    
    supervisor->ruleInit(process_pid);
    return process_pid;
}

void ProcessManager::start_supervisor(pid_t starter_pid) {
    Logger::getInstance().log(Logger::Verbosity::INFO, "%d ", 44);
    int notifyFd = fd_bridge->recv_fd();
    if (notifyFd == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "recv_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "%d", 47);


    supervisor->run(notifyFd);
}

void ProcessManager::process_starter() {

    downgrade_privileges();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Process starter prctl error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: starting seccomp filter installation");
    int notifyFd = installNotifyFilter();

    if (fd_bridge->send_fd(notifyFd) == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "send_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: sent fd");

    while (runnable) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: waiting for command to start");

        Strings task;
        int res = task_bridge->recv_strings(task);
        if (res == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Faield to recv task to start: %s", strerror(errno));
            continue;
        }
        Logger::getInstance().log(Logger::Verbosity::INFO, "Command: '%s'\tLog path: %s", task.str1.c_str(), task.str2.c_str());

        int stdoutFd = open((task.str2 + ".out").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        int stderrFd = open((task.str2 + ".err").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);

        if (stdoutFd < 0 || stderrFd < 0) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Error opening files for redirection: %s", strerror(errno));
        }
        pid_t targetPid = fork();
        if (targetPid == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s", strerror(errno));
            return;
        }

        if (targetPid != 0) {   
            if (started_pids_bridge->send_int(targetPid) == -1) {
                Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to send started process descriptor: %s", strerror(errno));
            }
            Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: process started with PID: %d", targetPid);
            close(stdoutFd);
            close(stderrFd);
        } else {
            dup2(stdoutFd, STDOUT_FILENO);
            dup2(stderrFd, STDERR_FILENO);

            close(stdoutFd);
            close(stderrFd);

            kill(getpid(), SIGSTOP);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process resumed");
            execl("/bin/sh", "sh", "-c", task.str1.c_str(), (char *) NULL);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process finished");
            exit(EXIT_SUCCESS);
        }
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: finished execution");
}

int ProcessManager::addRule(pid_t pid, Rule rule, std::vector<int> syscalls) {
    return supervisor->addRule(pid, rule, syscalls);
}

std::vector<int> ProcessManager::updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) {
    return supervisor->updateRules(pid, del_rules_id, new_rules);
}