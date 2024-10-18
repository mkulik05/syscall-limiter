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


Supervisor::Supervisor(pid_t starter_pid) {
    this->starter_pid = starter_pid;  
    this->pid = getpid();  
}
void Supervisor::run(int notifyFd) {
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

        // printf("\tS: got notification (ID %#llx) for PID %d\n",
            //    req->id, req->pid);

        resp->id = req->id;
        // Code that starts processes is allowed to execute any syscall
        if (req->pid == this->starter_pid)
        {
            resp->error = 0;
            resp->val = 0;
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }
        else
        {
            switch (req->data.nr)
            {
            // case SYS_mkdir:
            //     handle_mkdir(req, resp, notifyFd);
            //     break;

            case SYS_write:
                handle_write(req, resp, notifyFd);
                break;
            case SYS_statx:
                resp->error = -EACCES;
                resp->flags = 0;
                // for (;;) {}
                break;
            case SYS_getdents64:
                handle_getdents(req, resp, notifyFd);
                // std::cout << std::endl << std::endl << std::endl<< std::endl<< std::endl<< std::endl << std::endl;
                // for (;;) {}
                break;
            case SYS_getdents:
                handle_getdents(req, resp, notifyFd);
                // std::cout << std::endl << std::endl << std::endl<< std::endl<< std::endl<< std::endl << std::endl;
                // for (;;) {}
                break;
            default:
                resp->error = 0;
                resp->val = 0;
                resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                // printf("\tS: allowing system call (ID %#llx) %d\n", req->id, req->data.nr);
                break;
            }
        }
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