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
#include <csignal>

#include <QApplication>

#include "gui/MainW/MainW.h"
#include "logic/Supervisor/Manager/Supervisor.h"
#include "logic/ProcessManager/ProcessManager.h"

std::vector<pid_t> pids;

ProcessManager* process_manager = nullptr;


void signalHandler(int sig_n) {
    if (process_manager != nullptr) {
        process_manager->broadcast_signal(sig_n);
    }
    if (sig_n == SIGINT) {
        exit(1);
    }
}


void setSygHandlers() {
    std::signal(SIGKILL, signalHandler);
    std::signal(SIGINT, signalHandler);
    std::signal(SIGCONT, signalHandler);
    std::signal(SIGSTOP, signalHandler);
}

const char *program_pathname;
int main(int argc, char *argv[])
{
    program_pathname = argv[0];
    setSygHandlers();
    setbuf(stdout, NULL);
    
    QApplication app(argc, argv);

    MainW window;
    window.show();

    return app.exec();
}