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

#include "Supervisor/Manager/Supervisor.h"
#include "seccomp/seccomp.h"
#include "ProcessManager/ProcessManager.h"

std::vector<pid_t> pids;


int main(int argc, char *argv[])
{
;

    setbuf(stdout, NULL);

    ProcessManager* process_manager = new ProcessManager();
    process_manager->startProcess("dolphin");
    process_manager->startProcess("dolphin");
    process_manager->startProcess("kate");
    
    for(;;) { }

    exit(EXIT_SUCCESS);
}