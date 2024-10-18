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
#include "../Supervisor/Manager/Supervisor.h"
#include "../seccomp/seccomp.h"
#include "../ProcessManager/ProcessManager.h"

/* Close a pair of sockets created by socketpair() */
void closeSocketPair(int sockPair[2])
{
    if (close(sockPair[0]) == -1)
        err(EXIT_FAILURE, "closeSocketPair-close-0");
    if (close(sockPair[1]) == -1)
        err(EXIT_FAILURE, "closeSocketPair-close-1");
}

/* Send the file descriptor 'fd' over the connected UNIX domain socket
   'sockfd'. Returns 0 on success, or -1 on error. */

int sendfd(int sockfd, int fd)
{

    int data;
    struct iovec iov;
    struct msghdr msgh;
    struct cmsghdr *cmsgp;

    /* Allocate a char array of suitable size to hold the ancillary data.
       However, since this buffer is in reality a 'struct cmsghdr', use a
       union to ensure that it is suitably aligned. */
    union
    {
        char buf[CMSG_SPACE(sizeof(int))];
        /* Space large enough to hold an 'int' */
        struct cmsghdr align;
    } controlMsg;

    /* The 'msg_name' field can be used to specify the address of the
       destination socket when sending a datagram. However, we do not
       need to use this field because 'sockfd' is a connected socket. */

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    /* On Linux, we must transmit at least one byte of real data in
       order to send ancillary data. We transmit an arbitrary integer
       whose value is ignored by recvfd(). */

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data;
    iov.iov_len = sizeof(int);
    data = 12345;

    /* Set 'msghdr' fields that describe ancillary data */

    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);

    /* Set up ancillary data describing file descriptor to send */

    cmsgp = CMSG_FIRSTHDR(&msgh);
    cmsgp->cmsg_level = SOL_SOCKET;
    cmsgp->cmsg_type = SCM_RIGHTS;
    cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));

    /* Send real plus ancillary data */

    if (sendmsg(sockfd, &msgh, 0) == -1)
        return -1;

    return 0;
}

/* Receive a file descriptor on a connected UNIX domain socket. Returns
   the received file descriptor on success, or -1 on error. */

int recvfd(int sockfd)
{
    int data, fd;
    ssize_t nr;
    struct iovec iov;
    struct msghdr msgh;

    /* Allocate a char buffer for the ancillary data. See the comments
       in sendfd() */
    union
    {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } controlMsg;
    struct cmsghdr *cmsgp;

    /* The 'msg_name' field can be used to obtain the address of the
       sending socket. However, we do not need this information. */

    msgh.msg_name = NULL;
    msgh.msg_namelen = 0;

    /* Specify buffer for receiving real data */

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    iov.iov_base = &data; /* Real data is an 'int' */
    iov.iov_len = sizeof(int);

    /* Set 'msghdr' fields that describe ancillary data */

    msgh.msg_control = controlMsg.buf;
    msgh.msg_controllen = sizeof(controlMsg.buf);

    /* Receive real plus ancillary data; real data is ignored */

    nr = recvmsg(sockfd, &msgh, 0);
    if (nr == -1)
        return -1;

    cmsgp = CMSG_FIRSTHDR(&msgh);

    /* Check the validity of the 'cmsghdr' */

    if (cmsgp == NULL || cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) || cmsgp->cmsg_level != SOL_SOCKET || cmsgp->cmsg_type != SCM_RIGHTS)
    {
        errno = EINVAL;
        return -1;
    }

    /* Return the received file descriptor to our caller */

    memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
    return fd;
}

void sigchldHandler(int sig)
{
    char msg[] = "\tS: target has terminated; bye\n";

    write(STDOUT_FILENO, msg, sizeof(msg) - 1);
    _exit(EXIT_SUCCESS);
}

int seccomp(unsigned int operation, unsigned int flags, void *args)
{
    return syscall(SYS_seccomp, operation, flags, args);
}




/* Access the memory of the target process in order to fetch the
   pathname referred to by the system call argument 'argNum' in
   'req->data.args[]'.  The pathname is returned in 'path',
   a buffer of 'len' bytes allocated by the caller.

   Returns true if the pathname is successfully fetched, and false
   otherwise. For possible causes of failure, see the comments below. */

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
