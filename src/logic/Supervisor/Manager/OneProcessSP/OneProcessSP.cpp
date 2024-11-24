#include <err.h>
#include <errno.h>
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
#include <sstream>
#include <fstream>

#include "OneProcessSP.h"
#include "../../../seccomp/seccomp.h"
#include "../../handlers/handlers.h"
#include "../../../Logger/Logger.h"

#define ALLOWED_SYSCALLS_N 6

OneProcessSP::OneProcessSP(pid_t starter_pid) : Supervisor(starter_pid) {}

pid_t get_tgid(int pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *file = fopen(path, "r");
    if (!file) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to get tgid: %s for pid: %d", strerror(errno), pid);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Tgid:", 5) == 0) {
            long tgid;
            if (sscanf(line, "Tgid:\t%ld", &tgid) == 1) {
                fclose(file);
                return tgid;
            }
        }
    }

    fclose(file);
    fprintf(stderr, "Tgid not found in %s\n", path);
    return -1;
}

pid_t getParentPID(pid_t pid)
{
    std::ifstream statFile("/proc/" + std::to_string(pid) + "/stat");
    if (!statFile.is_open())
    {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to open stat file for PID: %d", pid);
        return -1;
    }

    std::string line;
    if (std::getline(statFile, line))
    {
        std::istringstream iss(line);
        std::string token;
        for (int i = 0; i < 3; ++i)
        {
            iss >> token;
        }
        pid_t ppid;
        iss >> ppid;

        return ppid;
    }

    Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to read parent PID for PID: %d", pid);
    return -1;
}


void OneProcessSP::handle_syscall(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd)
{
    resp->error = 0;
    resp->val = 0;
    resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

    if (req->pid == starter_pid)
    {
        Logger::getInstance().log(Logger::Verbosity::INFO, "STARTER Syscall n: %d; pid: %d", req->data.nr, req->pid);
        return;
    }

    if (curr_syscalls_n <= ALLOWED_SYSCALLS_N) {
        curr_syscalls_n++;
        return;
    }

    // Logger::getInstance().log(Logger::Verbosity::INFO, "Syscall n: %d; pid: %d", req->data.nr, req->pid);
    
    if ((this->map_all_rules.size() != 0) && (this->map_all_rules.count(req->pid) == 0))
    {
        Logger::getInstance().log(Logger::Verbosity::DEBUG, "Finding rules for PID: %d", req->pid);
        int pid = req->pid;
        while (pid != 1)
        {
            pid_t pid1 = getParentPID(pid);
            pid_t pid2 = get_tgid(pid);
            Logger::getInstance().log(Logger::Verbosity::DEBUG, "PID LOOKUP results: search pid: %d, ppid: %d, tgid: %d", pid, pid1, pid2);
            
            if (pid2 != pid1) {
                pid = pid2;
                if (this->map_all_rules.count(pid) != 0)
                {
                    Logger::getInstance().log(Logger::Verbosity::DEBUG, "TGID found: %d", pid);
                    map_all_rules[req->pid] = map_all_rules[pid];
                    map_pid_rules[req->pid] = map_pid_rules[pid];
                    for (int i = 0; i < map_pid_rules[pid].size(); i++)
                    {
                        int r_id = map_pid_rules[pid][i];
                        map_rules_info[r_id].pids.push_back(req->pid);
                    }
                    break;
                }
            }

            if (pid1 == -1)
                return;

            pid = pid1;

            if (this->map_all_rules.count(pid) != 0)
            {
                Logger::getInstance().log(Logger::Verbosity::DEBUG, "PID found: %d", pid);
                map_all_rules[req->pid] = map_all_rules[pid];
                map_pid_rules[req->pid] = map_pid_rules[pid];
                for (int i = 0; i < map_pid_rules[req->pid].size(); i++)
                {
                    int r_id = map_pid_rules[req->pid][i];
                    map_rules_info[r_id].pids.push_back(req->pid);
                }
                break;
            }
        }
        Logger::getInstance().log(Logger::Verbosity::DEBUG, "Found rules for PID: %d", pid);
    }

    // printMap(map_all_rules[req->pid]);
    if (this->map_all_rules.count(req->pid) == 0)
        return;

    if (this->map_all_rules[req->pid].count(req->data.nr) == 0)
        return;

    if (map_handlers.count(req->data.nr) != 0)
    {
        map_handlers[req->data.nr](req, resp, notifyFd, this->map_all_rules[req->pid][req->data.nr]);
    }
}

int OneProcessSP::addRuleUnsync(pid_t pid, Rule rule, std::vector<int> syscalls)
{

    int id = std::rand();
    rule.rule_id = id;
    this->map_rules_info[id] = RuleInfo{{pid}, syscalls};

    for (int i = 0; i < syscalls.size(); i++)
    {
        this->map_all_rules[pid][syscalls[i]].push_back(rule);
    }

    if (this->map_pid_rules.count(pid) == 0)
    {
        map_pid_rules[pid] = {id};
    }
    else
    {
        map_pid_rules[pid].push_back(id);
    }

    return id;
}

void OneProcessSP::deleteRuleUnsync(int rule_id)
{
    RuleInfo info = this->map_rules_info[rule_id];
    for (int j = 0; j < info.pids.size(); j++)
    {
        int pid = info.pids[j];
        for (int i = 0; i < info.vec_syscalls.size(); i++)
        {
            int del_i = -1;
            for (size_t k = 0; k < this->map_all_rules[pid][info.vec_syscalls[i]].size(); k++)
            {
                if (this->map_all_rules[pid][info.vec_syscalls[i]][k].rule_id == rule_id)
                {
                    del_i = k;
                    break;
                }
            }
            if (del_i != -1)
            {
                this->map_all_rules[pid][info.vec_syscalls[i]].erase(this->map_all_rules[pid][info.vec_syscalls[i]].begin() + del_i);

            }

            if (map_all_rules[pid][info.vec_syscalls[i]].size() == 0) {
                map_all_rules[pid].erase(info.vec_syscalls[i]);
            }
            
        }

        if (map_all_rules[pid].size() == 0) {
            map_all_rules.erase(pid);
        }
        
    }

    this->map_rules_info.erase(rule_id);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Deleted rule with ID: %d", rule_id);
}

int OneProcessSP::updateRule(pid_t pid, int rule_id, Rule rule)
{
    sem_wait(this->semaphore);
    std::vector<int> vec_syscalls = this->map_rules_info[rule_id].vec_syscalls;
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











// Debug prints
void printRuleType(RuleType type)
{
    switch (type)
    {
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

void printMap(const std::map<int, std::vector<Rule>> &myMap)
{
    for (const auto &pair : myMap)
    {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Key: %d", pair.first);
        for (const auto &rule : pair.second)
        {
            Logger::getInstance().log(Logger::Verbosity::INFO, "  Rule ID: %d, Type: ", rule.rule_id);
            printRuleType(rule.type);
            Logger::getInstance().log(Logger::Verbosity::INFO, ", Path: %s", rule.path.c_str());
        }
    }
}

void printMap2(const std::map<int, MapHandler> &myMap)
{
    for (const auto &pair : myMap)
    {
        Logger::getInstance().log(Logger::Verbosity::INFO, "K: %d", pair.first);
    }
}

void printMap3(const std::unordered_map<int, std::map<int, std::vector<Rule>>> &myMap)
{
    for (const auto &pidPair : myMap)
    {
        int pid = pidPair.first;
        Logger::getInstance().log(Logger::Verbosity::INFO, "Process PID: %d", pid);
        
        for (const auto &innerPair : pidPair.second)
        {
            int key = innerPair.first;
            Logger::getInstance().log(Logger::Verbosity::INFO, "  Key: %d", key);
            
            for (const auto &rule : innerPair.second)
            {
                Logger::getInstance().log(Logger::Verbosity::INFO, "    Rule ID: %d, Type: ", rule.rule_id);
                printRuleType(rule.type);
                Logger::getInstance().log(Logger::Verbosity::INFO, ", Path: %s\n", rule.path.c_str());
            }
        }
    }
}


void printRuleInfo(const std::unordered_map<int, RuleInfo> &map_rules_info) {
    for (const auto &pair : map_rules_info) {
        int ruleKey = pair.first;
        const RuleInfo &ruleInfo = pair.second;

        Logger::getInstance().log(Logger::Verbosity::INFO, "Rule Key: %d", ruleKey);

        Logger::getInstance().log(Logger::Verbosity::INFO, "  PIDs: ");
        for (const int pid : ruleInfo.pids) {
            Logger::getInstance().log(Logger::Verbosity::INFO, "    %d", pid);
        }
        Logger::getInstance().log(Logger::Verbosity::INFO, "  System Calls: ");
        for (const int syscall : ruleInfo.vec_syscalls) {
            Logger::getInstance().log(Logger::Verbosity::INFO, "    %d", syscall);
        }
    }
}