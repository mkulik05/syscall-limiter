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
#include "../../Supervisor/Manager/Supervisor.h"
#include "../../seccomp/seccomp.h"
#include "../../ProcessManager/ProcessManager.h"
#include "handlers.h"
#include "../../Logger/Logger.h"

bool getTargetPathname(struct seccomp_notif *req, int notifyFd,
                  int argNum, char *path, size_t len);

void checkPathesRule(std::string path, seccomp_notif_resp *resp, std::vector<Rule>& rules) {
    for (int i = 0; i < rules.size(); i++) {
        Rule rule = rules[i];
        switch (rule.type) {
        case DENY_ALWAYS:
            resp->error = -EACCES;
            resp->flags = 0;
            return;

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

void handle_path_restriction(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd, std::vector<Rule>& rules) {
    char path[PATH_MAX];
    bool pathOK = getTargetPathname(req, notifyFd, 0, path, sizeof(path));

    if (!pathOK) {
        resp->error = -EINVAL;
        resp->flags = 0;
        return;
    }
    checkPathesRule(path, resp, rules);
}

void handle_fd_restriction(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd, std::vector<Rule>& rules) {
    bool pathOK;
    char path[PATH_MAX];

    int fd = req->data.args[0];
    char fdPath[PATH_MAX];

    snprintf(fdPath, sizeof(fdPath), "/proc/%d/fd/%d", req->pid, fd);
    ssize_t nread = readlink(fdPath, path, sizeof(path) - 1);
    if (nread != -1)
        path[nread] = '\0'; 

    if (nread == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to read link for FD: %d", fd);
        return;
    }
    checkPathesRule(path, resp, rules);
}

void handle_openat_restriction(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd, std::vector<Rule>& rules) {
    char path[PATH_MAX];
    int dirfd = req->data.args[0]; // dirfd
    char path_arg2[PATH_MAX];
    bool pathOK = getTargetPathname(req, notifyFd, 1, path_arg2, sizeof(path_arg2));

    if (!pathOK) {
        resp->error = -EINVAL;
        resp->flags = 0;
        return;
    }

    Logger::getInstance().log(Logger::Verbosity::DEBUG, "Openat syscall: ");
    if (dirfd == AT_FDCWD) {
        if (realpath(path_arg2, path) == nullptr) {
            int fd = open(path_arg2, O_CREAT);
            if (realpath(path_arg2, path) == nullptr) {
                resp->error = -ENOENT;
                resp->flags = 0;
                close(fd);
                unlink(path_arg2);
                return;
            }
            close(fd);
            unlink(path_arg2);
        }
        Logger::getInstance().log(Logger::Verbosity::INFO, "Path_arg2: %s, Res path: %s", path_arg2, path);            
    } else {
        char resolvedPath[PATH_MAX];
        snprintf(resolvedPath, sizeof(resolvedPath), "/proc/%d/fd/%d", req->pid, dirfd);
        ssize_t nread = readlink(resolvedPath, path, sizeof(path) - 1);
        if (nread == -1) {
            resp->error = -EBADF;
            resp->flags = 0;
            return;
        }
        path[nread] = '\0'; 
        if (realpath((std::string(path) + "/" + std::string(path_arg2)).c_str(), path) == nullptr) {
            resp->error = -ENOENT;
            resp->flags = 0;
            return;
        }
    }

    checkPathesRule(path, resp, rules);
}

bool getTargetPathname(struct seccomp_notif *req, int notifyFd, int argNum, char *path, size_t len) {
    int procMemFd;
    char procMemPath[PATH_MAX];
    ssize_t nread;

    snprintf(procMemPath, sizeof(procMemPath), "/proc/%d/mem", req->pid);

    procMemFd = open(procMemPath, O_RDONLY | O_CLOEXEC);
    if (procMemFd == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to open /proc/%d/mem: %s", req->pid, strerror(errno));
        return false;
    }

    if (!cookieIsValid(notifyFd, req->id)) {
        close(procMemFd);
        return false;
    }

    nread = pread(procMemFd, path, len, req->data.args[argNum]);
    close(procMemFd);

    if (nread <= 0) {
        Logger::getInstance().log(Logger::Verbosity::WARNING, "No valid pathname read for PID %d", req->pid);
        return false;
    }

    if (!cookieIsValid(notifyFd, req->id)) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Notification ID check failed for PID %d", req->pid);
        return false;
    }

    if (strnlen(path, nread) < nread) {
        return true;
    }

    return false;
}


void handle_get_dents_restriction(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd, std::vector<Rule>& rules) {
    bool pathOK;
    char path[PATH_MAX];

    int fd = req->data.args[0];
    char fdPath[PATH_MAX];

    snprintf(fdPath, sizeof(fdPath), "/proc/%d/fd/%d", req->pid, fd);
    ssize_t nread = readlink(fdPath, path, sizeof(path) - 1);
    if (nread != -1)
        path[nread] = '\0'; 

    if (nread == -1) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to read link for FD: %d", fd);
        return;
    }
    Logger::getInstance().log(Logger::Verbosity::INFO, "GET DENTS, path: %s", path);
    checkPathesRule(path, resp, rules);
}

void add_handlers(std::unordered_map<int, MapHandler>& map) {
    map[SYS_openat] = handle_openat_restriction;
    map[SYS_open] = handle_path_restriction;
    map[SYS_write] = handle_fd_restriction;
    map[SYS_openat2] = handle_openat_restriction;
    map[SYS_mkdir] = handle_path_restriction;
    map[SYS_open] = handle_path_restriction;
    map[SYS_read] = handle_fd_restriction;
    map[SYS_write] = handle_fd_restriction;
    map[SYS_close] = handle_fd_restriction;
    map[SYS_lseek] = handle_fd_restriction;
    map[SYS_fstat] = handle_fd_restriction;
    map[SYS_fsync] = handle_fd_restriction;
    map[SYS_flock] = handle_fd_restriction;
    map[SYS_getdents] = handle_get_dents_restriction;
    map[SYS_getdents64] = handle_get_dents_restriction;
    map[SYS_sendfile] = handle_fd_restriction;
}