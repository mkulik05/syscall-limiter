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
#include <sys/mman.h>
#include <sstream>
#include <fstream>
#include "Supervisor.h"
#include "../../seccomp/seccomp.h"
#include "../../ProcessManager/ProcessManager.h"
#include "../handlers/handlers.h"
#include "../../Logger/Logger.h" 

Supervisor::Supervisor(pid_t starter_pid) : rnd_gen(std::random_device{}()), rnd_dis(0, 4294967295) {
    add_handlers(this->map_handlers);
    this->starter_pid = starter_pid;
    semaphore = sem_open("/sync_access", O_CREAT, 0666, 1);
    sem_init(semaphore, 0, 1);
    this->pid = getpid();
    Logger::getInstance().log(Logger::Verbosity::INFO, "Supervisor initialized with starter PID: %d", starter_pid);
}

void Supervisor::run(int notifyFd) {
    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;

    allocSeccompNotifBuffers(&req, &resp, &sizes);

    Logger::getInstance().log(Logger::Verbosity::INFO, "Supervisor started");

    for (;;) {
        memset(req, 0, sizes.seccomp_notif);
        Logger::getInstance().log(Logger::Verbosity::DEBUG, "Waiting for notification on FD: %d", notifyFd);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "SECCOMP_IOCTL_NOTIF_RECV error: %s", strerror(errno));
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "ioctl-SECCOMP_IOCTL_NOTIF_RECV failed");
        } else {
            Logger::getInstance().log(Logger::Verbosity::INFO, "SECCOMP_IOCTL_NOTIF_RECV OK");
        }

        resp->id = req->id;

        sem_wait(this->semaphore);
        this->handle_syscall(req, resp, notifyFd);
        sem_post(this->semaphore);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1) {
            if (errno == ENOENT) {
                Logger::getInstance().log(Logger::Verbosity::WARNING, "Response failed with ENOENT; perhaps target process's syscall was interrupted by a signal?");
            } else {
                Logger::getInstance().log(Logger::Verbosity::ERROR, "ioctl-SECCOMP_IOCTL_NOTIF_SEND error: %s", strerror(errno));
            }
        }
    }

    free(req);
    free(resp);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Supervisor terminating");
    exit(EXIT_SUCCESS);
}

void printRuleType(RuleType type) {
    switch (type) {
    case DENY_PATH_ACCESS:
        Logger::getInstance().log(Logger::Verbosity::INFO, "Rule Type: DENY_PATH_ACCESS");
        break;
    case DENY_ALWAYS:
        Logger::getInstance().log(Logger::Verbosity::INFO, "Rule Type: DENY_ALWAYS");
        break;
    case ALLOW_WITH_LOG:
        Logger::getInstance().log(Logger::Verbosity::INFO, "Rule Type: ALLOW_WITH_LOG");
        break;
    }
}

void printMap(const std::map<int, std::vector<Rule>> &myMap) {
    for (const auto &pair : myMap) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Key: %d", pair.first);
        for (const auto &rule : pair.second) {
            Logger::getInstance().log(Logger::Verbosity::INFO, "  Rule ID: %d, Type: ", rule.rule_id);
            printRuleType(rule.type);
            Logger::getInstance().log(Logger::Verbosity::INFO, ", Path: %s", rule.path.c_str());
        }
    }
}

void printMap2(const std::map<int, MapHandler> &myMap) {
    for (const auto &pair : myMap) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "K: %d", pair.first);
    }
}

pid_t getParentPID(pid_t pid) {
    std::ifstream statFile("/proc/" + std::to_string(pid) + "/stat");
    if (!statFile.is_open()) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to open stat file for PID: %d", pid);
        return -1;
    }

    std::string line;
    if (std::getline(statFile, line)) {
        std::istringstream iss(line);
        std::string token;
        for (int i = 0; i < 3; ++i) {
            iss >> token;
        }
        pid_t ppid;
        iss >> ppid;
        return ppid;
    }

    Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to read parent PID for PID: %d", pid);
    return -1;
}

void Supervisor::handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd) {
    resp->error = 0;
    resp->val = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

    if (req->pid == this->starter_pid)
    {
        Logger::getInstance().log(Logger::Verbosity::INFO, "STARTER Syscall n: %d; pid: %d", req->data.nr, req->pid);
        return;
    }

    Logger::getInstance().log(Logger::Verbosity::INFO, "Syscall n: %d; pid: %d", req->data.nr, req->pid);

    if (this->map_all_rules.count(req->pid) == 0) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Finding rules for PID: %d", req->pid);
        int pid = req->pid;
        while (pid != 1) {
            pid = getParentPID(pid);
            if (pid == -1) return;
            if (this->map_all_rules.count(pid) != 0) {
                Logger::getInstance().log(Logger::Verbosity::INFO, "PID found: %d", pid);
                map_all_rules[req->pid] = map_all_rules[pid];
                for (int i = 0; i < map_pid_rules[pid].size(); i++) {
                    int r_id = map_pid_rules[pid][i];
                    map_rules_info[r_id].pids.push_back(req->pid);
                }
                break;
            }
        }
    }

    if (this->map_all_rules.count(req->pid) == 0) return;

    if (this->map_all_rules[req->pid].count(req->data.nr) == 0)
        return;

    if (this->map_handlers.count(req->data.nr) != 0) {
        this->map_handlers[req->data.nr](req, resp, notifyFd, this->map_all_rules[req->pid][req->data.nr]);
    }
}

int Supervisor::addRule(pid_t pid, Rule rule, std::vector<int> syscalls) {
    sem_wait(this->semaphore);

    int id = std::rand();
    rule.rule_id = id;
    this->map_rules_info[id] = RuleInfo{{pid}, syscalls};

    for (int i = 0; i < syscalls.size(); i++) {
        this->map_all_rules[pid][syscalls[i]].push_back(rule);
    }

    if (this->map_pid_rules.count(pid) == 0) {
        map_pid_rules[pid] = {id};
    } else {
        map_pid_rules[pid].push_back(id);
    }

    sem_post(this->semaphore);
    return id;
}

void Supervisor::deleteRule(int rule_id) {
    sem_wait(this->semaphore);
    RuleInfo info = this->map_rules_info[rule_id];
    for (int i = 0; i < info.vec_syscalls.size(); i++) {
        for (int j = 0; j < info.pids.size(); j++) {
            int pid = info.pids[j];
            int del_i = -1;
            for (size_t j = 0; j < this->map_all_rules[pid][info.vec_syscalls[i]].size(); j++) {
                if (this->map_all_rules[pid][info.vec_syscalls[i]][j].rule_id == rule_id) {
                    del_i = j;
                    break;
                }
            }
            if (del_i != -1) {
                this->map_all_rules[pid][info.vec_syscalls[i]].erase(this->map_all_rules[pid][info.vec_syscalls[i]].begin() + del_i);
            }
        }
    }
    this->map_rules_info.erase(rule_id);
    sem_post(this->semaphore);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Deleted rule with ID: %d", rule_id);
}

int Supervisor::updateRule(pid_t pid, int rule_id, Rule rule) {
    std::vector<int> vec_syscalls = this->map_rules_info[rule_id].vec_syscalls;
    this->deleteRule(rule_id);
    int id = this->addRule(pid, rule, vec_syscalls);
    this->map_rules_info.erase(rule_id);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Updated rule ID: %d to new ID: %d", rule_id, id);
    return id;
}