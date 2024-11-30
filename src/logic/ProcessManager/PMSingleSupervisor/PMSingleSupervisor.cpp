#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <qlogging.h>
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
#include <vector>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/resource.h>
#include <QDebug>


#include "../../SocketBridge/SocketBridge.h"
#include "../../Supervisor/Manager/ManyProcessesSP/ManyProcessesSP.h"
#include "../../seccomp/seccomp.h"
#include "PMSingleSupervisor.h"
#include "../../Logger/Logger.h" 


PMSingleSupervisor::~PMSingleSupervisor() {

    kill(this->process_starter_pid, SIGTERM);
    for (int i = 0; i < this->startedIDs.size(); i++) {
        kill(this->startedIDs[i], SIGTERM);
    }

    this->supervisor->stopRunning();
    pthread_kill(this->thread_supervisor.native_handle(), SIGINT);
    this->thread_supervisor.join();

    runnable = false;
    pthread_kill(this->thread_process_starter.native_handle(), SIGINT);
    this->thread_process_starter.join();
}

PMSingleSupervisor::PMSingleSupervisor() : ProcessManager()
{   
    runnable = true;
    pid_t targetPid = fork();

    if (targetPid == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (targetPid > 0) {
        this->supervisor = new ManyProcessesSP(targetPid);
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

void PMSingleSupervisor::start_supervisor(pid_t starter_pid) {
    int notifyFd = fd_bridge->recv_fd();
    if (notifyFd == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "recv_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    supervisor->run(notifyFd);
}

void PMSingleSupervisor::prepare_starter() {
    downgrade_privileges();
    
	Logger::getInstance().log(
	Logger::Verbosity::INFO,
	"Process starter: starting seccomp filter installation");
	
	int notifyFd = installNotifyFilter();

	if (fd_bridge -> send_fd(notifyFd) == -1) {
		Logger::getInstance().log(Logger::Verbosity::ERROR, "send_fd error: %s",
			strerror(errno));
		exit(EXIT_FAILURE);
	}
	Logger::getInstance().log(Logger::Verbosity::INFO,
		"Process starter: sent fd");
}

void PMSingleSupervisor::start_process(Strings & task, int & stdoutFd, int & stderrFd) {
    pid_t targetPid = fork();
    if (targetPid == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s",
            strerror(errno));
    }

    if (targetPid != 0) {
        if (started_pids_bridge -> send_int(targetPid) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR,
                "Failed to send started process descriptor: %s",
                strerror(errno));
        }
        Logger::getInstance().log(Logger::Verbosity::INFO,
            "Process starter: process started with PID: %d",
            targetPid);
        close(stdoutFd);
        close(stderrFd);
    } else {
        dup2(stdoutFd, STDOUT_FILENO);
        dup2(stderrFd, STDERR_FILENO);

        close(stdoutFd);
        close(stderrFd);

        kill(getpid(), SIGSTOP);
        Logger::getInstance().log(Logger::Verbosity::DEBUG,
            "Started process resumed");
        execl("/bin/sh", "sh", "-c", task.str1.c_str(), (char * ) NULL);
        Logger::getInstance().log(Logger::Verbosity::DEBUG,
            "Started process finished");
        exit(EXIT_SUCCESS);
    }
}

int PMSingleSupervisor::addProcess(std::string cmd, std::string log_path) {
    int pid = ProcessManager::addProcess(cmd, log_path);
    supervisor->ruleInit(pid);
    return pid;
}

int PMSingleSupervisor::addRule(pid_t pid, Rule rule, std::vector<int> syscalls) {
    return supervisor->addRule(pid, rule, syscalls);
}

std::vector<int> PMSingleSupervisor::updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) {
    return supervisor->updateRules(pid, del_rules_id, new_rules);
}