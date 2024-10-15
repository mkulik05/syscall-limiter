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
#include "../supervisor/supervisor.h"
#include "../seccomp/seccomp.h"
#include "../supervised_p/supervised_p.h"

ProcessManager::ProcessManager()
{
    this->start_process_msg_type = 1;
    int sockPair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1)
        err(EXIT_FAILURE, "socketpair");

    pid_t targetPid = fork();

    if (targetPid == -1)
        err(EXIT_FAILURE, "fork");

    if (targetPid > 0) {
        std::cout << "Process starter pid: " << targetPid << std::endl;
        this->start_supervisor(sockPair, targetPid);
        this->process_starter_pid = targetPid;
        return;
    }    
    
    this->process_starter(sockPair);
    exit(EXIT_SUCCESS);
}

void ProcessManager::start_supervisor(int sockPair[2], pid_t starter_pid) {
    std::cout << 44 << " ";
    pid_t targetPid = fork();

    if (targetPid == -1)
        err(EXIT_FAILURE, "fork");

    if (targetPid > 0) {
        this->supervisor_pid = targetPid;
        return;
    }

    std::cout << 45 << " ";
    int notifyFd = recvfd(sockPair[1]);
    std::cout << 46 << " " << notifyFd << std::endl;
    if (notifyFd == -1)
        err(EXIT_FAILURE, "recvfd");
    std::cout << 47;
    closeSocketPair(sockPair);

    handleNotifications(notifyFd, starter_pid);
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
    return 0;
}

void ProcessManager::process_starter(int sockPair[2]) {

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

    if (sendfd(sockPair[0], notifyFd) == -1)
        err(EXIT_FAILURE, "sendfd");

    if (close(notifyFd) == -1)
        err(EXIT_FAILURE, "close-target-notify-fd");

    closeSocketPair(sockPair);

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
        
        // TODO: return pid of created process
        if (targetPid == 0) {   
            execl("/bin/sh", "sh", "-c", command.substr(0, n).c_str(), (char *) NULL);
            exit(EXIT_SUCCESS);
        }
        counter++;
    }

}