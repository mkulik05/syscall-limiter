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
#include <fstream>
#include <sstream>

#include "../../Supervisor/Manager/Supervisor.h"
#include "../../seccomp/seccomp.h"
#include "PMSingleSupervisor.h"
#include "../../Logger/Logger.h" 


PMSingleSupervisor::~PMSingleSupervisor() {
    kill(this->process_starter_pid, SIGTERM);
    for (int i = 0; i < this->startedPIDs.size(); i++) {
        kill(this->startedPIDs[i], SIGTERM);
    }
    kill(this->supervisor->pid, SIGTERM);
    this->thread_supervisor.~thread();
}

PMSingleSupervisor::PMSingleSupervisor() : ProcessManager()
{   
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

void PMSingleSupervisor::startProcess(pid_t pid) {    
    usleep(100000); // 100ms

    Logger::getInstance().log(Logger::Verbosity::INFO, "SIGCONT sender: Starting process with PID: %d", pid);
    kill(pid, SIGCONT);
}


void PMSingleSupervisor::stopProcess(pid_t pid) {
    kill(pid, SIGTERM);
}


pid_t PMSingleSupervisor::addProcess(std::string cmd, std::string log_path) {
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

void PMSingleSupervisor::start_supervisor(pid_t starter_pid) {
    Logger::getInstance().log(Logger::Verbosity::INFO, "%d ", 44);
    int notifyFd = fd_bridge->recv_fd();
    if (notifyFd == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "recv_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "%d", 47);


    supervisor->run(notifyFd);
}

void PMSingleSupervisor::process_starter() {

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

    for (;;) {
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
            std::cerr << "Error opening files for redirection." << std::endl;
            return;
        }
        pid_t targetPid = fork();
        if (targetPid == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s", strerror(errno));
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

int PMSingleSupervisor::addRule(pid_t pid, Rule rule, std::vector<int> syscalls) {
    return supervisor->addRule(pid, rule, syscalls);
}

std::vector<int> PMSingleSupervisor::updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) {
    return supervisor->updateRules(pid, del_rules_id, new_rules);
}