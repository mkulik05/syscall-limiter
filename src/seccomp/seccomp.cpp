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

/* Allocate buffers for the seccomp user-space notification request and
   response structures. It is the caller's responsibility to free the
   buffers returned via 'req' and 'resp'. */

void allocSeccompNotifBuffers(struct seccomp_notif **req,
                         struct seccomp_notif_resp **resp,
                         struct seccomp_notif_sizes *sizes)
{
    size_t resp_size;

    /* Discover the sizes of the structures that are used to receive
       notifications and send notification responses, and allocate
       buffers of those sizes. */

    if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, sizes) == -1)
        err(EXIT_FAILURE, "seccomp-SECCOMP_GET_NOTIF_SIZES");

    *req = static_cast<seccomp_notif *>(malloc(sizes->seccomp_notif));
    if (*req == NULL)
        err(EXIT_FAILURE, "malloc-seccomp_notif");

    /* When allocating the response buffer, we must allow for the fact
       that the user-space binary may have been built with user-space
       headers where 'struct seccomp_notif_resp' is bigger than the
       response buffer expected by the (older) kernel. Therefore, we
       allocate a buffer that is the maximum of the two sizes. This
       ensures that if the supervisor places bytes into the response
       structure that are past the response size that the kernel expects,
       then the supervisor is not touching an invalid memory location. */

    resp_size = sizes->seccomp_notif_resp;
    if (sizeof(struct seccomp_notif_resp) > resp_size)
        resp_size = sizeof(struct seccomp_notif_resp);

    *resp = static_cast<seccomp_notif_resp *>(malloc(resp_size));
    if (*resp == NULL)
        err(EXIT_FAILURE, "malloc-seccomp_notif_resp");
}

/* Check that the notification ID provided by a SECCOMP_IOCTL_NOTIF_RECV
   operation is still valid. It will no longer be valid if the target
   process has terminated or is no longer blocked in the system call that
   generated the notification (because it was interrupted by a signal).

   This operation can be used when doing such things as accessing
   /proc/PID files in the target process in order to avoid TOCTOU race
   conditions where the PID that is returned by SECCOMP_IOCTL_NOTIF_RECV
   terminates and is reused by another process. */

bool cookieIsValid(int notifyFd, uint64_t id)
{
    return ioctl(notifyFd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) == 0;
}



/* The following is the x86-64-specific BPF boilerplate code for checking
   that the BPF program is running on the right architecture + ABI. At
   completion of these instructions, the accumulator contains the system
   call number. */

/* For the x32 ABI, all system call numbers have bit 30 set */

#define X32_SYSCALL_BIT 0x40000000

#define X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR                         \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS,                                \
             (offsetof(struct seccomp_data, arch))),                  \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2), \
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,                            \
                 (offsetof(struct seccomp_data, nr))),                \
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),   \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

/* installNotifyFilter() installs a seccomp filter that generates
   user-space notifications (SECCOMP_RET_USER_NOTIF) when the process
   calls mkdir(2); the filter allows all other system calls.

   The function return value is a file descriptor from which the
   user-space notifications can be fetched. */

int
installNotifyFilter(void)
{
    int notifyFd;

    struct sock_filter filter[] = {
        X86_64_CHECK_ARCH_AND_LOAD_SYSCALL_NR,

        /* Check for specific syscalls to trigger notification to user-space supervisor */

        // Example for a few syscalls (expand as needed)

        // BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
        // BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

       

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mkdir, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
        // BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
        // BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

        // BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
        // BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

        // Add additional syscalls here...

        /* Allow all other syscalls */
        // BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = ARRAY_SIZE(filter),
        .filter = filter,
    };

    /* Install the filter with the SECCOMP_FILTER_FLAG_NEW_LISTENER flag;
       as a result, seccomp() returns a notification file descriptor. */

    notifyFd = seccomp(SECCOMP_SET_MODE_FILTER,
                       SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);

    if (notifyFd == -1)
        err(EXIT_FAILURE, "seccomp-install-notify-filter");

    return notifyFd;
}

