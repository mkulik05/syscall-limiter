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

bool getTargetPathname(struct seccomp_notif *req, int notifyFd,
                  int argNum, char *path, size_t len);

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

    // std::cout << path;
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


bool getTargetPathname(struct seccomp_notif *req, int notifyFd,
                  int argNum, char *path, size_t len)
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
