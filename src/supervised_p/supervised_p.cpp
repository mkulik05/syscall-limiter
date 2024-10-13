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

#include "../assistance/assistance.h"
#include "../supervisor/supervisor.h"
#include "../seccomp/seccomp.h"
#include "../supervised_p/supervised_p.h"

/* Implementation of the target process; create a child process that:

   (1) installs a seccomp filter with the
       SECCOMP_FILTER_FLAG_NEW_LISTENER flag;
   (2) writes the seccomp notification file descriptor returned from
       the previous step onto the UNIX domain socket, 'sockPair[0]';
   (3) calls mkdir(2) for each element of 'argv'.

   The function return value in the parent is the PID of the child
   process; the child does not return from this function. */

pid_t targetProcess(int sockPair[2], char *argv[], void *addr)
{
    int notifyFd, s;
    pid_t targetPid;

    targetPid = fork();

    if (targetPid == -1)
        err(EXIT_FAILURE, "fork");

    if (targetPid > 0) /* In parent, return PID of child */
        return targetPid;

    /* Child falls through to here */

    printf("T: PID = %ld\n", (long)getpid());

    /* Install seccomp filter(s) */

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        err(EXIT_FAILURE, "prctl");
        
    setbuf(stdout, NULL);
    notifyFd = installNotifyFilter();

    /* Pass the notification file descriptor to the tracing process over
       a UNIX domain socket */

    //*(int*)addr = notifyFd;
    // std::cout << "Done";
    // std::cout << notifyFd << std::endl;
    // std::cout << *(int*)addr;
    if (sendfd(sockPair[0], notifyFd) == -1)
        err(EXIT_FAILURE, "sendfd");

    // /* Notification and socket FDs are no longer needed in target */

    if (close(notifyFd) == -1)
        err(EXIT_FAILURE, "close-target-notify-fd");

    closeSocketPair(sockPair);

    /* Perform a mkdir() call for each of the command-line arguments */

    for (char **ap = argv; *ap != NULL; ap++)
    {
        // printf("\nT: about to mkdir(\"%s\")\n", *ap);

        s = mkdir(*ap, 0700);
        // s = mkdir(*ap, 0700);
        // s = mkdir(*ap, 0700);
        if (s == -1)
            perror("T: ERROR: mkdir(2)");
        else
            printf("T: SUCCESS: mkdir(2) returned %d\n", s);
    }

    printf("\nT: terminating\n");
    exit(EXIT_SUCCESS);
}
