#define _GNU_SOURCE
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

#include "assistance/assistance.h"
#include "supervisor/supervisor.h"
#include "seccomp/seccomp.h"
#include "supervised_p/supervised_p.h"

std::vector<pid_t> pids;


int main(int argc, char *argv[])
{
    int sockPair[2];
    struct sigaction sa;

    setbuf(stdout, NULL);

    if (argc < 2)
    {
        fprintf(stderr, "At least one pathname argument is required\n");
        exit(EXIT_FAILURE);
    }

    /* Create a UNIX domain socket that is used to pass the seccomp
       notification file descriptor from the target process to the
       supervisor process. */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockPair) == -1)
        err(EXIT_FAILURE, "socketpair");

    /* Create a child process--the "target"--that installs seccomp
       filtering. The target process writes the seccomp notification
       file descriptor onto 'sockPair[0]' and then calls mkdir(2) for
       each directory in the command-line arguments. */

    void *addr = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    *(int *)addr = -1;
    (void)targetProcess(sockPair, &argv[optind], addr);

    /* Catch SIGCHLD when the target terminates, so that the
       supervisor can also terminate. */

    sa.sa_handler = sigchldHandler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
        err(EXIT_FAILURE, "sigaction");

    supervisor(sockPair, addr);

    exit(EXIT_SUCCESS);
}