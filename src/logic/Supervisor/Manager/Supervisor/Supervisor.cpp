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

#include "Supervisor.h"
#include "../../../seccomp/seccomp.h"
#include "../../handlers/handlers.h"
#include "../../../Logger/Logger.h"


Supervisor::Supervisor(pid_t starter_pid) : rnd_gen(std::random_device{}()), rnd_dis(0, 4294967295)
{
    runnable = true;
    curr_syscalls_n = 0;
    add_handlers(this->map_handlers);
    this->starter_pid = starter_pid;
    semaphore = sem_open("/sync_access", O_CREAT, 0666, 1);
    sem_init(semaphore, 0, 1);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Supervisor initialized with starter PID: %d", starter_pid);
}

void Supervisor::stopRunning() {
    runnable = false;
}

void Supervisor::run(int notifyFd)
{
    Logger::getInstance().log(Logger::Verbosity::DEBUG, "Supervisor euid now: %d", geteuid());
    

    struct seccomp_notif *req;
    struct seccomp_notif_resp *resp;
    struct seccomp_notif_sizes sizes;

    allocSeccompNotifBuffers(&req, &resp, &sizes);

    Logger::getInstance().log(Logger::Verbosity::INFO, "Supervisor started");

    while (runnable)
    {
        memset(req, 0, sizes.seccomp_notif);
        // Logger::getInstance().log(Logger::Verbosity::DEBUG, "Waiting for notification on FD: %d", notifyFd);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_RECV, req) == -1)
        {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "SECCOMP_IOCTL_NOTIF_RECV error: %s", strerror(errno));
            continue;
        }

        resp->id = req->id;

        sem_wait(this->semaphore);
        this->handle_syscall(req, resp, notifyFd);
        sem_post(this->semaphore);

        if (ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_SEND, resp) == -1)
        {
            if (errno == ENOENT)
            {
                Logger::getInstance().log(Logger::Verbosity::WARNING, "Response failed with ENOENT; perhaps target process's syscall was interrupted by a signal?");
            }
            else
            {
                Logger::getInstance().log(Logger::Verbosity::ERROR, "ioctl-SECCOMP_IOCTL_NOTIF_SEND error: %s", strerror(errno));
            }
        }
    }

    free(req);
    free(resp);
    Logger::getInstance().log(Logger::Verbosity::INFO, "Supervisor terminating");
    exit(EXIT_SUCCESS);
}

int Supervisor::addRule(pid_t pid, Rule rule, std::vector<int> syscalls)
{
    sem_wait(this->semaphore);
    int res = this->addRuleUnsync(pid, rule, syscalls);
    sem_post(this->semaphore);
    return res;
}

void Supervisor::deleteRule(int rule_id)
{
    sem_wait(this->semaphore);
    this->deleteRuleUnsync(rule_id);
    sem_post(this->semaphore);
}


std::vector<int> Supervisor::updateRules(pid_t pid, std::vector<int> del_rules_id, std::vector<std::pair<Rule, std::vector<int>>> new_rules)
{


    std::vector<int> res = {};
    sem_wait(this->semaphore);

    for (int i = 0; i < del_rules_id.size(); i++)
    {
        this->deleteRuleUnsync(del_rules_id[i]);
    }

    for (int i = 0; i < new_rules.size(); i++)
    {
        res.push_back(this->addRuleUnsync(pid, new_rules[i].first, new_rules[i].second));
    }

    sem_post(this->semaphore);
    return res;
}