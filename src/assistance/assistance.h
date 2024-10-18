#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
int seccomp(unsigned int operation, unsigned int flags, void *args);
void sigchldHandler(int sig);
bool getTargetPathname(struct seccomp_notif *req, int notifyFd, int argNum, char *path, size_t len);