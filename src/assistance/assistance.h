#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
int seccomp(unsigned int operation, unsigned int flags, void *args);
int sendfd(int sockfd, int fd);
int recvfd(int sockfd);
void closeSocketPair(int sockPair[2]);
void sigchldHandler(int sig);
bool getTargetPathname(struct seccomp_notif *req, int notifyFd, int argNum, char *path, size_t len);