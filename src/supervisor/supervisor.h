void handleNotifications(int notifyFd, pid_t starter_pid);
void allocSeccompNotifBuffers(struct seccomp_notif **req,
                         struct seccomp_notif_resp **resp,
                         struct seccomp_notif_sizes *sizes);