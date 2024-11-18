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


QStringList syscalls = {};
std::unordered_map<QString, int> syscallMap = {{"open", SYS_open}, {"close", SYS_close}, {"stat", SYS_stat}, {"fstat", SYS_fstat}, {"lstat", SYS_lstat}, {"newfstatat", SYS_newfstatat}, {"access", SYS_access}, {"faccessat", SYS_faccessat}, {"faccessat2", SYS_faccessat2}, {"mkdir", SYS_mkdir}, {"mkdirat", SYS_mkdirat}, {"rmdir", SYS_rmdir}, {"creat", SYS_creat}, {"unlink", SYS_unlink}, {"unlinkat", SYS_unlinkat}, {"readlink", SYS_readlink}, {"readlinkat", SYS_readlinkat}, {"chmod", SYS_chmod}, {"fchmod", SYS_fchmod}, {"fchmodat", SYS_fchmodat}, {"chown", SYS_chown}, {"fchown", SYS_fchown}, {"lchown", SYS_lchown}, {"fchownat", SYS_fchownat}, {"chdir", SYS_chdir}, {"fchdir", SYS_fchdir}, {"statfs", SYS_statfs}, {"fstatfs", SYS_fstatfs}, {"umount2", SYS_umount2}, {"openat", SYS_openat}, {"openat2", SYS_openat2}, {"mknod", SYS_mknod}, {"mknodat", SYS_mknodat}, {"utimensat", SYS_utimensat}, {"futimesat", SYS_futimesat}, {"name_to_handle_at", SYS_name_to_handle_at}, {"open_by_handle_at", SYS_open_by_handle_at}, {"read", SYS_read}, {"write", SYS_write}, {"getdents", SYS_getdents}, {"getdents64", SYS_getdents64}, {"lseek", SYS_lseek}, {"fsync", SYS_fsync}, {"flock", SYS_flock}, {"sendfile", SYS_sendfile}};
std::unordered_map<int, QString> invertedSyscallMap = {};
std::unordered_map<QString, QStringList> groups = {
    {"GRP_fs_access", { "open", "close", "stat", "fstat", "lstat", "newfstatat", "access", "faccessat", 
        "faccessat2", "mkdir", "mkdirat", "rmdir", "creat", "unlink", "unlinkat", "readlink", 
        "readlinkat", "chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat", 
        "chdir", "fchdir", "statfs", "fstatfs", "umount2", "openat", "openat2", "mknod", 
        "mknodat", "utimensat", "futimesat", "name_to_handle_at", "open_by_handle_at", 
        "read", "write", "getdents", "getdents64", "lseek", "fsync", "flock", "sendfile"}}, 
    {"GRP_file_ops", { "open", "close", "read", "write", "readlink", "readlinkat", "stat", "fstat", 
        "lstat", "openat", "openat2", "creat", "unlink", "unlinkat", "flock", "fsync", "sendfile"
    }},
    {"GRP_dirs_calls", {"mkdir", "mkdirat", "rmdir", "chdir", "fchdir"}},
    {"GRP_files_iter", {"getdents", "getdents64"}},
    {"GRP_permissions", { "access", "faccessat", "faccessat2", "chmod", "fchmod", "fchmodat", "chown", 
        "fchown", "lchown", "fchownat" }}
};

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


    uid_t euid = geteuid();
    if (euid != 0) {
        std::cout << "Program should be run with root" << std::endl;
        exit(EXIT_SUCCESS);
    }

    for (auto it = groups.begin(); it != groups.end(); ++it) {
        syscalls.append(it->first);
    }
    for (auto it = syscallMap.begin(); it != syscallMap.end(); ++it) {
        syscalls.append(it->first);
        invertedSyscallMap[it->second] = it->first;
    }

    std::sort(syscalls.begin() + groups.size(), syscalls.end());

    QApplication app(argc, argv);

    MainW window;
    window.show();

    return app.exec();
}