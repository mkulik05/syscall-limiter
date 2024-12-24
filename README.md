# Syscall limiter
The goal of this project is to limit syscalls that started process may do. Limiting was implemented for all filesystem related syscalls (or almost all:)).
You may either limit all such syscalls or specify restricted pathes. Those rules may be saved for future use. There is also ability to limit RAM that process uses. 

This functionality is implemented using seccomp and cgroup linux features.
