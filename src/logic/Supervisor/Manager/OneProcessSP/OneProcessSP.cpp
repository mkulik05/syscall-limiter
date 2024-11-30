#include <err.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
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
#include <sys/mman.h>

#include "OneProcessSP.h"
#include "../../../seccomp/seccomp.h"
#include "../../handlers/handlers.h"
#include "../../../Logger/Logger.h"

#define ALLOWED_SYSCALLS_N 6

OneProcessSP::OneProcessSP(pid_t starter_pid) : Supervisor(starter_pid) {
    is_supervising = false;
}

void OneProcessSP::startSupervising() {
    is_supervising = true;
}

void OneProcessSP::handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd)
{
    resp->error = 0;
    resp->val = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

    if (!is_supervising) {
        return;
    }

    if (req->pid == starter_pid)
    {
        Logger::getInstance().log(Logger::Verbosity::INFO, "STARTER Syscall n: %d; pid: %d", req->data.nr, req->pid);
        return;
    }

    Logger::getInstance().log(Logger::Verbosity::INFO, "Syscall n: %d; pid: %d", req->data.nr, req->pid);
    if (this->map_all_rules.count(req->data.nr) == 0)
        return;

    if (map_handlers.count(req->data.nr) != 0)
    {
        map_handlers[req->data.nr](req, resp, notifyFd, this->map_all_rules[req->data.nr]);
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "Result err: %d, flags: %d", resp->error, resp->flags);
}

int OneProcessSP::addRuleUnsync(pid_t pid, Rule rule, std::vector<int> syscalls)
{

    int id = std::rand();
    rule.rule_id = id;
    this->map_rules_info[id] = syscalls;

    for (int i = 0; i < syscalls.size(); i++)
    {
        if (this->map_all_rules.count(syscalls[i]) == 0) {
            this->map_all_rules[syscalls[i]] = {};
        }
        this->map_all_rules[syscalls[i]].push_back(rule);
    }


    return id;
}

void OneProcessSP::deleteRuleUnsync(int rule_id)
{
    std::vector<int> syscalls = this->map_rules_info[rule_id];
    for (int i = 0; i < syscalls.size(); i++)
    {
        int del_i = -1;
        for (size_t k = 0; k < this->map_all_rules[syscalls[i]].size(); k++)
        {
            if (this->map_all_rules[syscalls[i]][k].rule_id == rule_id)
            {
                del_i = k;
                break;
            }
        }
        if (del_i != -1)
        {
            this->map_all_rules[syscalls[i]].erase(this->map_all_rules[syscalls[i]].begin() + del_i);

        }

        if (map_all_rules[syscalls[i]].size() == 0) {
            map_all_rules.erase(syscalls[i]);
        }
        
    }

    this->map_rules_info.erase(rule_id);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Deleted rule with ID: %d", rule_id);
}

int OneProcessSP::updateRule(pid_t pid, int rule_id, Rule rule)
{
    sem_wait(this->semaphore);
    std::vector<int> vec_syscalls = this->map_rules_info[rule_id];
    this->deleteRule(rule_id);
    int id = this->addRule(pid, rule, vec_syscalls);
    this->map_rules_info.erase(rule_id);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Updated rule ID: %d to new ID: %d", rule_id, id);
    sem_post(this->semaphore);
    return id;
}

void OneProcessSP::ruleInit(pid_t pid) {
    sem_wait(this->semaphore);
    this->map_all_rules[pid] = {};
    sem_post(this->semaphore);
}
