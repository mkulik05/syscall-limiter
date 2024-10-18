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

#include "../../assistance/assistance.h"
#include "../../Supervisor/Manager/Supervisor.h"
#include "../../seccomp/seccomp.h"
#include "../../ProcessManager/ProcessManager.h"

void handle_mkdir(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd)
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
        printf("\tS: spoofing error for invalid pathname (%s)\n",
               strerror(-resp->error));
    }
    else if (strncmp(path, "/tmp/", strlen("/tmp/")) == 0)
    {
        printf("\tS: executing: mkdir(\"%s\", %#llo)\n",
               path, req->data.args[1]);

        if (mkdir(path, req->data.args[1]) == 0)
        {
            resp->error = 0;
            resp->val = strlen(path);
            printf("\tS: success! spoofed return = %lld\n", resp->val);
        }
        else
        {
            resp->error = -errno;
            printf("\tS: failure! (errno = %d; %s)\n", errno, strerror(errno));
        }
    }
    else if (strncmp(path, "./", strlen("./")) == 0)
    {
        resp->error = resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        printf("\tS: target can execute system call\n");
    }
    else
    {
        resp->error = -EOPNOTSUPP;
        printf("\tS: spoofing error response (%s)\n", strerror(-resp->error));
    }

    printf("\tS: sending response (flags = %#x; val = %lld; error = %d)\n",
           resp->flags, resp->val, resp->error);
}

void handle_write(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd)
{
    // printf("\tS: intercepted write system call\n");
    bool pathOK;
    char path[PATH_MAX];

    int fd = req->data.args[0]; // Get file descriptor
    char fdPath[PATH_MAX];

    // Retrieve the pathname corresponding to the file descriptor
    snprintf(fdPath, sizeof(fdPath), "/proc/%d/fd/%d", req->pid, fd);
    ssize_t nread = readlink(fdPath, path, sizeof(path) - 1);
    if (nread != -1)
        path[nread] = '\0'; // Null-terminate the path

    
    // resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp->val = 0;

    if (nread == -1)
    {
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        // printf("\tS: unable to resolve file descriptor path (%s)\n", strerror(errno));
    }
    else if (strncmp(path, "/tmp/", strlen("/tmp/")) == 0)
    {
        // Deny write access to files in /home/a/own_files/
        resp->error = -EACCES;
        resp->flags = 0;
        // printf("\tS: denying write to %s (EACCES)\n", path);
    }
    else
    {
        // Allow the write if it's not in /home/a/own_files/
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        // printf("\tS: allowing write to %s\n", path);
    }
}


void handle_getdents(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd)
{
    // printf("\tS: intercepted write system call\n");
    bool pathOK;
    char path[PATH_MAX];

    int fd = req->data.args[0]; // Get file descriptor
    char fdPath[PATH_MAX];

    // Retrieve the pathname corresponding to the file descriptor
    snprintf(fdPath, sizeof(fdPath), "/proc/%d/fd/%d", req->pid, fd);
    ssize_t nread = readlink(fdPath, path, sizeof(path) - 1);
    if (nread != -1)
        path[nread] = '\0'; // Null-terminate the path

    std::cout << path;
    // resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp->val = 0;

    if (nread == -1)
    {
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        // printf("\tS: unable to resolve file descriptor path (%s)\n", strerror(errno));
    }
    else if (strncmp(path, "/tmp", strlen("/tmp")) == 0)
    {
        // Deny write access to files in /home/a/own_files/
        // for (;;) {}
        resp->error = -EACCES;
        resp->flags = 0;
        // printf("\tS: denying write to %s (EACCES)\n", path);
    }
    else
    {
        // Allow the write if it's not in /home/a/own_files/
        resp->error = 0;
        resp->val = 0;
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        // printf("\tS: allowing write to %s\n", path);
    }
}