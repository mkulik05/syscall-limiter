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


#include "Supervisor.h"
#include "../../seccomp/seccomp.h"
#include "../../ProcessManager/ProcessManager.h"
#include "../handlers/handlers.h"

Supervisor::Supervisor(pid_t starter_pid) : rnd_gen(std::random_device{}()), rnd_dis(0, 4294967295)
{
    add_handlers(this->map_handlers);
    this->starter_pid = starter_pid;
    semaphore = sem_open("/sync_access", O_CREAT, 0666, 1);
    sem_init(semaphore, 0, 1);
    this->pid = getpid();
}

void Supervisor::run(int notifyFd)
{
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;

    allocSeccompNotifBuffers(&req, &resp, &sizes);

    std::cout << "Supervisor started" << std::endl;
    for (;;)
    {
        memset(req, 0, sizes.seccomp_notif);
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1)
        {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "ioctl-SECCOMP_IOCTL_NOTIF_RECV");
        }

        resp->id = req->id;
        
        std::cout << "Sem wait start\n";
        sem_wait(this->semaphore);
        std::cout << "Sem wait passed\n";
        this->handle_syscall(req, resp, notifyFd);
        sem_post(this->semaphore);
        
        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1)
        {
            if (errno == ENOENT)
                printf("\tS: response failed with ENOENT; "
                       "perhaps target process's syscall was "
                       "interrupted by a signal?\n");
            else
                perror("ioctl-SECCOMP_IOCTL_NOTIF_SEND");
        }
    }

    free(req);
    free(resp);
    printf("\tS: terminating **********\n");
    exit(EXIT_SUCCESS);
}

void Supervisor::handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd) {
    std::cout << "01010101010101010";
    resp->error = 0;
    resp->val = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    std::cout << "\n" <<  this->map_all_rules.count(req->pid) << "\n";
    if (this->map_all_rules.count(req->pid) == 0) return;
    if (this->map_handlers.count(req->data.nr) != 0) {
        this->map_handlers[req->data.nr](req, resp, notifyFd, this->map_all_rules[req->pid][req->data.nr]);
    }
}

int Supervisor::addRule(pid_t pid, Rule rule, std::vector<int> syscalls)
{

    std::cout << "lalalallalalalalala";
    sem_wait(this->semaphore);
    std::cout << "+++++++++++++++++++";
    int id = 5;//this->rnd_dis(this->rnd_gen);
    std::cout << "################";
    rule.rule_id = id;
    std::cout << "------------------";
    this->map_rules_ids[id] = RuleInfo{pid, syscalls};
    
    for (int i = 0; i < syscalls.size(); i++)
    {
        this->map_all_rules[pid][syscalls[i]].push_back(rule);
    }

    std::cout << "\n" <<  this->map_all_rules.count(pid) << "\n";
    for (;;){}
    sem_post(this->semaphore);
    return id;
}

void Supervisor::deleteRule(pid_t pid, int rule_id)
{
    sem_wait(this->semaphore);
    RuleInfo info = this->map_rules_ids[rule_id];
    for (int i = 0; i < info.vec_syscalls.size(); i++)
    {
        int del_i = -1;
        for (int j = 0; j < this->map_all_rules[pid][info.vec_syscalls[i]].size(); j++)
        {
            if (this->map_all_rules[pid][info.vec_syscalls[i]][j].rule_id == rule_id)
            {
                del_i = j;
            }
        }
        if (del_i != -1)
        {
            this->map_all_rules[pid][info.vec_syscalls[i]].erase(this->map_all_rules[pid][info.vec_syscalls[i]].begin() + del_i);
        }
    }
    this->map_rules_ids.erase(rule_id);
    sem_post(this->semaphore);
}

int Supervisor::updateRule(pid_t pid, int rule_id, Rule rule) {
    this->deleteRule(pid, rule_id);
    int id = this->addRule(pid, rule, this->map_rules_ids[rule_id].vec_syscalls);
    this->map_rules_ids.erase(rule_id);
    return id;
}
