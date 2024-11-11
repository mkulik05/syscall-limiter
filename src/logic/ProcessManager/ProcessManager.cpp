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

#include "../Supervisor/Manager/Supervisor.h"
#include "../seccomp/seccomp.h"
#include "../ProcessManager/ProcessManager.h"
#include "../Logger/Logger.h" 


extern const char *program_pathname;

ProcessManager::ProcessManager()
{   
    this->start_process_msg_type = 1;
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
        });
        this->process_starter_pid = targetPid;
        return;
    }    
    
    this->process_starter();
    exit(EXIT_SUCCESS);
}

bool is_process_suspended(pid_t pid) {
    Logger::getInstance().log(Logger::Verbosity::INFO, "\n\nlala-%d-=-=-=-=-=-=-=-=%d-=-=-=-=-=-=-=-=\n\n", pid, getpid());
    std::ifstream status_file("/proc/" + std::to_string(pid) + "/status");
    std::string line;

    if (!status_file.is_open()) {
        Logger::getInstance().log(Logger::Verbosity::WARNING, "\nCase1: Unable to open status file for PID %d", pid);
        return false;
    }
    status_file.sync();
    while (std::getline(status_file, line)) {
        if (line.find("State:") != std::string::npos) {
            status_file.sync();
            Logger::getInstance().log(Logger::Verbosity::INFO, "\n\n\n%s\n\n\n", line.c_str());
            if ((line.find("T (stopped)") != std::string::npos) || (line.find("S (sleeping)") != std::string::npos)) {
                return true;
            } else {
                Logger::getInstance().log(Logger::Verbosity::WARNING, "\nCase2: Process %d is not suspended: %s\n\n", pid, line.c_str());
                return false;
            }
        }
    }
    Logger::getInstance().log(Logger::Verbosity::WARNING, "\nCase3: Process state not found for PID %d\n", pid);
    return false;
}

void ProcessManager::startProcess(pid_t pid) {    
    // waiting for target process to start 
    // while (kill(pid, 0) == -1) {
    //     Logger::getInstance().log(Logger::Verbosity::INFO, "SIGCONT sender: waiting for process to start: %d", pid);
    //     if (errno != ESRCH) {
    //         break;
    //     }
    //     // 10ms
    //     usleep(10000);
    // }

    // waiting for target process to start 
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

    delete this->fd_bridge;

    this->supervisor->run(notifyFd);
}

void ProcessManager::process_starter() {
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
    Logger::getInstance().log(Logger::Verbosity::INFO, "\n%d", msgid);
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
            // Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process resumed");
            execl("/bin/sh", "sh", "-c", command.substr(0, n).c_str(), (char *) NULL);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "Started process finished");
            for(;;){}
            exit(EXIT_SUCCESS);
        }
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Process starter: finished execution");
}