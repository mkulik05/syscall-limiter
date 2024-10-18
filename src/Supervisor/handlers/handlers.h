#include <linux/seccomp.h>

void handle_mkdir(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd);
void handle_write(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd);
void handle_getdents(seccomp_notif *req, seccomp_notif_resp *resp, int notifyFd);