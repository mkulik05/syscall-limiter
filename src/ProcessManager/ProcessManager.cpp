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

#include "../assistance/assistance.h"
#include "../Supervisor/Manager/Supervisor.h"
#include "../seccomp/seccomp.h"
#include "../ProcessManager/ProcessManager.h"

ProcessManager::ProcessManager()
{
    this->start_process_msg_type = 1;
    this->startedPIDs = std::vector<pid_t>();
    this->fd_bridge = new SocketBridge();
    this->started_pids_bridge = new SocketBridge();
    std::cout << this->started_pids_bridge->send_int(1);
    perror("fndjksfnjkdsnfjkds");
    std::cout << "Res: "<< this->started_pids_bridge->recv_int() << "lll";

    pid_t targetPid = fork();

    if (targetPid == -1)
        err(EXIT_FAILURE, "fork");

    if (targetPid > 0) {
        this->supervisor = new Supervisor(targetPid);
        std::cout << "Process starter pid: " << targetPid << std::endl;
        this->start_supervisor(targetPid);
        this->process_starter_pid = targetPid;
        return;
    }    
    
    this->process_starter();
    exit(EXIT_SUCCESS);
}

void ProcessManager::start_supervisor(pid_t starter_pid) {
    std::cout << 44 << " ";
    pid_t targetPid = fork();

    if (targetPid == -1)
        err(EXIT_FAILURE, "fork");

    if (targetPid > 0) {
        return;
    }

    std::cout << 45 << " ";
    int notifyFd = this->fd_bridge->recv_fd();
    std::cout << 46 << " " << notifyFd << std::endl;
    if (notifyFd == -1)
        err(EXIT_FAILURE, "recvfd");
    std::cout << 47;
    this->fd_bridge;

    delete this->fd_bridge;

    this->supervisor->run(notifyFd);
}

pid_t ProcessManager::startProcess(std::string cmd) {
    key_t key = ftok("tmp222", START_PROCESS_IPC_VALUE);
    int msgid = msgget(key, 0666 | IPC_CREAT);

    if (msgid == -1) {
        perror("msgget");
        return 1;
    }
    std::cout << "LLLLL";
    struct msg_buffer message;
    message.msg_type = this->start_process_msg_type;
    strncpy(message.msg_text, cmd.c_str(), sizeof(message.msg_text));
    this->start_process_msg_type += 1;
    if (msgsnd(msgid, &message, cmd.length(), 0) == -1) {
        perror("msgsnd");
        return 1;
    }
    int process_pid = this->started_pids_bridge->recv_int();
    this->startedPIDs.push_back(process_pid);
    return 0;
}

void ProcessManager::process_starter() {

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        err(EXIT_FAILURE, "prctl");
        
    key_t key = ftok("tmp222", START_PROCESS_IPC_VALUE);
    int msgid = msgget(key, 0666 | IPC_CREAT);
    std::cout << std::endl<< msgid;
    if (msgid == -1) {
        std::cout << 543;
        perror("msgget");
        return;
    }

    int notifyFd = installNotifyFilter();

    if (this->fd_bridge->send_fd(notifyFd) == -1)
        err(EXIT_FAILURE, "sendfd");

    if (close(notifyFd) == -1)
        err(EXIT_FAILURE, "close-target-notify-fd");

    struct msg_buffer message;

    long counter = 1;
    for (;;) {
        size_t n = msgrcv(msgid, &message, sizeof(message.msg_text), counter, 0);
        if (n == -1) {
            perror("msgrcv");
            return;
        }
        std::string command = message.msg_text;

        std::cout << "Command: " << command.substr(0, n) << "'" << std::endl;
        pid_t targetPid = fork();
        if (targetPid == -1) {
            perror("fork");
            break;
        }

        if (targetPid != 0) {   
            if (this->started_pids_bridge->send_int(targetPid) == -1)
                perror("Failed to send started process descriptor");
        } else {
            execl("/bin/sh", "sh", "-c", command.substr(0, n).c_str(), (char *) NULL);
            exit(EXIT_SUCCESS);
        }
        counter++;
    }

}