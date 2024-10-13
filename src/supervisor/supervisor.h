void supervisor(int sockPair[2], void *addr);
void allocSeccompNotifBuffers(struct seccomp_notif **req,
                         struct seccomp_notif_resp **resp,
                         struct seccomp_notif_sizes *sizes);