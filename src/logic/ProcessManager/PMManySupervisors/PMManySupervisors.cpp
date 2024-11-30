#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <qlogging.h>
#include <semaphore.h>
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
#include <thread>
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
#include "../../Supervisor/Manager/OneProcessSP/OneProcessSP.h"
#include "../../seccomp/seccomp.h"
#include "PMManySupervisors.h"
#include "../../Logger/Logger.h" 

#define STACK_SIZE 8 * 1024 * 1024

PMManySupervisors::~PMManySupervisors() {
    for (int i = 0; i < this->startedIDs.size(); i++) {
        kill(this->startedIDs[i], SIGTERM);
    }
    for (int i = 0; i < supervisors.size(); i++) {
        this->supervisors[i]->stopRunning();
        pthread_kill(this->thread_supervisors[i].native_handle(), SIGINT);
        this->thread_supervisors[i].join();
    }
    for (int i = 0; i < thread_processes.size(); i++) {
        thread_processes[i].join();
    }
}

static int processStarter(void* arg) {
    PMManySupervisors* instance = static_cast<PMManySupervisors*>(arg);
    instance->process_starter(); 
    return 0;
}

PMManySupervisors::PMManySupervisors() : ProcessManager()
{   
    map_pid_arr_i = {};
    runnable = true;
    supervisors = {};

    sem_supervisors = sem_open("/supervisors_sync_access", O_CREAT, 0666, 1);
    if (sem_supervisors == SEM_FAILED) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to open '/supervisors_sync_access' semaphore: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int r = sem_init(sem_supervisors, 0, 1);
    if (r == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to init '/supervisors_sync_access' semaphore: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    sem_threads = sem_open("/threads_sync_access", O_CREAT, 0666, 1);
    if (sem_supervisors == SEM_FAILED) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to open '/threads_sync_access' semaphore: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    int r2 = sem_init(sem_supervisors, 0, 1);
    if (r2 == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to init '/threads_sync_access' semaphore: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    void* stack = malloc(STACK_SIZE);
    if (!stack) {
        	Logger::getInstance().log(Logger::Verbosity::INFO,"Failed to allocate stack.");
	
        return;
    }
    pid_t targetPid = clone(processStarter, static_cast<char*>(stack) + STACK_SIZE, CLONE_VM | SIGCHLD, this);

    if (targetPid == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "fork error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (targetPid > 0) {
        process_starter_pid = targetPid;
        qInfo() << process_starter_pid;
        return;
    } 
}

void PMManySupervisors::startProcess(pid_t pid) {    
    usleep(100000); // 100ms

    Logger::getInstance().log(Logger::Verbosity::INFO, "SIGCONT sender: Starting process with PID: %d", pid);
    kill(pid, SIGCONT);
}


void PMManySupervisors::stopProcess(pid_t pid) {
    kill(pid, SIGTERM);
}

int PMManySupervisors::addProcess(std::string cmd, std::string log_path) {
    int pid = ProcessManager::addProcess(cmd, log_path);
    map_pid_arr_i[pid] = thread_processes.size() - 1;
    return pid;
}


void PMManySupervisors::start_process(Strings & task, int & stdoutFd, int & stderrFd) {
    sem_wait(sem_supervisors);
    sem_wait(sem_threads);

    // Creating new supervisor itself
    qInfo() << process_starter_pid;
    OneProcessSP *sp = new OneProcessSP(process_starter_pid);
    supervisors.push_back(sp);
    
    Logger::getInstance().log(Logger::Verbosity::DEBUG,
                "Process pid: %d, tgid: %d:", getpid(), gettid());

    thread_processes.emplace_back(std::thread([stdoutFd, stderrFd, task, sp, this]() {
        downgrade_privileges();

        int notifyFd = installNotifyFilter();

        if (fd_bridge -> send_fd(notifyFd) == -1) {
            exit(EXIT_FAILURE);
        }

         
        Logger::getInstance().log(Logger::Verbosity::DEBUG,
                "Created THREAD process pid: %d, tgid: %d:", getpid(), gettid());

        if (started_pids_bridge -> send_int(gettid()) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR,
                "Failed to send started process descriptor: %s",
                strerror(errno));
            exit(EXIT_FAILURE);
        }

        

        dup2(stdoutFd, STDOUT_FILENO);
        dup2(stderrFd, STDERR_FILENO); 

        close(stdoutFd);
        close(stderrFd);

        kill(getpid(), SIGSTOP);

        Logger::getInstance().log(Logger::Verbosity::DEBUG,
            "Started process resumed");

        sp->startSupervising();
        execl("/bin/sh", "sh", "-c", task.str1.c_str(), (char * ) NULL);
        Logger::getInstance().log(Logger::Verbosity::DEBUG,
            "Started process finished");
        exit(EXIT_SUCCESS);
    }));

    int notifyFd = fd_bridge->recv_fd();
    if (notifyFd == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "recv_fd error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    thread_supervisors.emplace_back(std::thread([sp, notifyFd]() {
        sp->run(notifyFd);
    }));

    sem_post(sem_supervisors);
    sem_post(sem_threads);
}

int PMManySupervisors::addRule(pid_t pid, Rule rule, std::vector<int> syscalls) {
    return supervisors[map_pid_arr_i[pid]]->addRule(pid, rule, syscalls);
}

std::vector<int> PMManySupervisors::updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules) {
    return supervisors[map_pid_arr_i[pid]]->updateRules(pid, del_rules_id, new_rules);
}