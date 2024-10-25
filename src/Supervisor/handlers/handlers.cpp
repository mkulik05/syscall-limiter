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

#include "../../Supervisor/Manager/Supervisor.h"
#include "../../seccomp/seccomp.h"
#include "../../ProcessManager/ProcessManager.h"
#include "handlers.h"


bool getTargetPathname(struct seccomp_notif *req, int notifyFd,
                  int argNum, char *path, size_t len);

void checkPathesRule(std::string path, seccomp_notif_resp *resp, std::vector<Rule>& rules) {
    for (int i = 0; i < rules.size(); i++) {
        Rule rule = rules[i];
        switch (rule.type)
        {
        case DENY_ALWAYS:
            resp->error = -EACCES;
            resp->flags = 0;
            return;
            break;
        
        case DENY_PATH_ACCESS:
            if (strncmp(path.c_str(), rule.path.c_str(), strlen(rule.path.c_str())) == 0) {
                resp->error = -EACCES;
                resp->flags = 0;
                return;
            }
            break;
        }   
    }
}

void handle_mkdir(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd, std::vector<Rule>& rules)
{
    printf("\tS: intercepted mkdir system call\n");
    bool pathOK;
    char path[PATH_MAX];
    pathOK = getTargetPathname(req, notifyFd, 0, path, sizeof(path));
    resp->flags = 0;
    resp->val = 0;

    if (!pathOK)
    {
        resp->error = -EINVAL;
        resp->flags = 0;
        return;
    }
    checkPathesRule(path, resp, rules);
}



void handle_path_restriction(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd, std::vector<Rule>& rules)
{
    bool pathOK;
    char path[PATH_MAX];

    int fd = req->data.args[0];
    char fdPath[PATH_MAX];

    snprintf(fdPath, sizeof(fdPath), "/proc/%d/fd/%d", req->pid, fd);
    ssize_t nread = readlink(fdPath, path, sizeof(path) - 1);
    if (nread != -1)
        path[nread] = '\0'; 

    if (nread == -1)
    {
        return;
    }
    checkPathesRule(path, resp, rules);
}

bool getTargetPathname(struct seccomp_notif *req, int notifyFd, int argNum, char *path, size_t len)
{
    int procMemFd;
    char procMemPath[PATH_MAX];
    ssize_t nread;

    snprintf(procMemPath, sizeof(procMemPath), "/proc/%d/mem", req->pid);

    procMemFd = open(procMemPath, O_RDONLY | O_CLOEXEC);
    if (procMemFd == -1)
        return false;

    /* Check that the process whose info we are accessing is still alive
       and blocked in the system call that caused the notification.
       If the SECCOMP_IOCTL_NOTIF_ID_VALID operation (performed in
       cookieIsValid()) succeeded, we know that the /proc/PID/mem file
       descriptor that we opened corresponded to the process for which we
       received a notification. If that process subsequently terminates,
       then read() on that file descriptor will return 0 (EOF). */

    if (!cookieIsValid(notifyFd, req->id))
    {
        close(procMemFd);
        return false;
    }

    /* Read bytes at the location containing the pathname argument */

    nread = pread(procMemFd, path, len, req->data.args[argNum]);

    close(procMemFd);

    if (nread <= 0)
        return false;

    /* Once again check that the notification ID is still valid. The
       case we are particularly concerned about here is that just
       before we fetched the pathname, the target's blocked system
       call was interrupted by a signal handler, and after the handler
       returned, the target carried on execution (past the interrupted
       system call). In that case, we have no guarantees about what we
       are reading, since the target's memory may have been arbitrarily
       changed by subsequent operations. */

    if (!cookieIsValid(notifyFd, req->id))
    {
        perror("\tS: notification ID check failed!!!");
        return false;
    }

    /* Even if the target's system call was not interrupted by a signal,
       we have no guarantees about what was in the memory of the target
       process. (The memory may have been modified by another thread, or
       even by an external attacking process.) We therefore treat the
       buffer returned by pread() as untrusted input. The buffer should
       contain a terminating null byte; if not, then we will trigger an
       error for the target process. */

    if (strnlen(path, nread) < nread)
        return true;

    return false;
}

void add_handlers(std::map<int, MapHandler>& map) {
    map[SYS_mkdir] = handle_mkdir;
    map[SYS_read] = handle_path_restriction;
    map[SYS_write] = handle_path_restriction;
    map[SYS_close] = handle_path_restriction;
    map[SYS_lseek] = handle_path_restriction;
    map[SYS_fstat] = handle_path_restriction;
    map[SYS_fsync] = handle_path_restriction;
    map[SYS_flock] = handle_path_restriction;
    map[SYS_getdents] = handle_path_restriction;
    map[SYS_getdents64] = handle_path_restriction;
    map[SYS_sendfile] = handle_path_restriction;
}