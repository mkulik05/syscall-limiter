#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <cstring>

#define BUF_SIZE 1024

struct linux_dirent {
    unsigned long  d_ino;     /* Inode number */
    unsigned long  d_off;     /* Not an offset; see below */
    unsigned short d_reclen;  /* Length of this linux_dirent */
    char           d_name[];  /* Filename (null-terminated) */
                        /* length is actually (d_reclen - 2 -
                        offsetof(struct linux_dirent, d_name)) */
    /*
    char           pad;       // Zero padding byte
    char           d_type;    // File type (only since Linux
                                // 2.6.4); offset is (d_reclen - 1)
    */
};

int main() {
    const char* dir_path = "/tmp";
    int fd = open(dir_path, O_RDONLY | O_DIRECTORY);
    if (fd == -1) {
        perror("open");
        return 1;
    }

    char buffer[BUF_SIZE];
    struct linux_dirent* d;
    ssize_t nread;
    int bpos;

    while (true) {
        nread = syscall(SYS_getdents, fd, buffer, BUF_SIZE);
        if (nread == -1) {
            perror("getdents");
            close(fd);
            return 1;
        }
        if (nread == 0) {
            break; // No more entries
        }

        for (bpos = 0; bpos < nread;) {
            d = (struct linux_dirent*)(buffer + bpos);
            std::cout << d->d_name << std::endl;
            bpos += d->d_reclen; 
        }
    }

    close(fd);
    return 0;
}