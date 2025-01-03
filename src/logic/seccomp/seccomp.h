#include <cstdint>
int seccomp(unsigned int operation, unsigned int flags, void *args);
bool cookieIsValid(int notifyFd, uint64_t id);
int installNotifyFilter(void);
void allocSeccompNotifBuffers(struct seccomp_notif **req,
                         struct seccomp_notif_resp **resp,
                         struct seccomp_notif_sizes *sizes);