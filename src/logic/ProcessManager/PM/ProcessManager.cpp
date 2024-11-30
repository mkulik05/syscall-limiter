#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pwd.h>
#include <signal.h>
#include <sstream>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "../../Logger/Logger.h"
#include "../../seccomp/seccomp.h"
#include "ProcessManager.h"

extern const char * program_pathname;

std::string getCgroupMountPoint();

ProcessManager::~ProcessManager() {
	delete this -> started_pids_bridge;
	delete this -> fd_bridge;
	delete this -> task_bridge;
	for (const auto & pair: map_cgroup) {
		int res = rmdir(pair.second.c_str());
		if (res != 0) {
			Logger::getInstance().log(Logger::Verbosity::ERROR,
				"Failed to remove cgroup: %s", strerror(errno));
		}
	}
}

ProcessManager::ProcessManager() {
	Logger::getInstance().setVerbosity(Logger::Verbosity::DEBUG);
	this -> cgroup_path = getCgroupMountPoint();
	this -> map_cgroup = {};
	this -> startedIDs = std::vector < pid_t > ();
	this -> fd_bridge = new SocketBridge();
	this -> started_pids_bridge = new SocketBridge();
	this -> task_bridge = new SocketBridge();
	this -> runnable = true;
}

std::string getCgroupMountPoint() {
	std::ifstream mountsFile("/proc/mounts");
	if (!mountsFile.is_open()) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Error opening /proc/mounts");
		return "";
	}

	std::string line;
	while (std::getline(mountsFile, line)) {
		std::istringstream iss(line);
		std::string device, mountPoint, fstype, options;

		if (iss >> device >> mountPoint >> fstype >> options) {
			if (mountPoint.find("cgroup") != std::string::npos) {
				mountsFile.close();
				return mountPoint;
			}
		}
	}

	mountsFile.close();
	return "";
}

pid_t ProcessManager::addProcess(std::string cmd, std::string log_path) {
	Strings buf = {
		cmd,
		log_path
	};
	int r = task_bridge -> send_strings(buf);
	if (r != 0) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Failed to send task: %s", strerror(errno));
		return -1;
	}
	Logger::getInstance().log(Logger::Verbosity::INFO,
		"Adding process: before receiving new proc fd");
	int process_pid = started_pids_bridge -> recv_int();
	Logger::getInstance().log(Logger::Verbosity::INFO, "process PID received: %d",
		process_pid);
	this -> startedIDs.push_back(process_pid);

	return process_pid;
}

int writeToFile(const std::string & path,
	const std::string & content) {
	std::ofstream file(path);
	if (file.is_open()) {
		file << content;
		file.close();
		return 0;
	} else {
		return -1;
	}
}

int ProcessManager::setMemTime(pid_t pid, std::string maxMem, int maxTime) {
	Logger::getInstance().log(Logger::Verbosity::DEBUG,
		"Updating maxMem and maxTime");

	Logger::getInstance().log(Logger::Verbosity::DEBUG, "euid is %d", getuid());

	if (cgroup_path == "") {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"cgroup_path is empty, skipping: %s",
			strerror(errno));
		return -1;
	}

	std::string path;
	if (this -> map_cgroup.count(pid) == 0) {
		path = cgroup_path + "/map_control-" + std::to_string(pid) + "-" +
			std::to_string(std::rand());
		if (mkdir(path.c_str(), 0777) == -1) {
			Logger::getInstance().log(Logger::Verbosity::ERROR,
				"Failed to create folder: %s", strerror(errno));
			return -1;
		}
		if (writeToFile(path + "/cgroup.procs", std::to_string(pid)) == -1) {
			Logger::getInstance().log(Logger::Verbosity::ERROR,
				"Failed to set cgroup pid: %s",
				strerror(errno));
			return -1;
		}
		this -> map_cgroup[pid] = path;
	} else {
		path = map_cgroup[pid];
	}
	if (writeToFile(path + "/memory.max", maxMem) == -1) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Failed to set cgroup memory.max: %s",
			strerror(errno));
		return -1;
	}

	if (writeToFile(path + "/memory.swap.max", "0") == -1) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Failed to set cgroup memory.swap.max: %s",
			strerror(errno));
		return -1;
	}

	return 0;
}

bool is_process_zombie(pid_t pid) {
	std::ifstream stat_file("/proc/" + std::to_string(pid) + "/stat");
	std::string line;

	if (!stat_file.is_open()) {
		return false;
	}

	if (std::getline(stat_file, line)) {
		std::istringstream iss(line);
		std::string token;
		int field_index = 0;

		while (iss >> token) {
			if (field_index == 2) {
				return (token == "Z");
			}
			field_index++;
		}
	}
	return false;
}

bool ProcessManager::is_process_running(pid_t pid) {
	return (kill(pid, 0) == 0) && (!is_process_zombie(pid));
}

void ProcessManager::downgrade_privileges() {
	struct stat info;
	stat(program_pathname, & info);
	struct passwd * pw = getpwuid(info.st_uid);
	if (setregid(info.st_gid, info.st_gid) != 0) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Failed to drop priviledges (setregid)");
		err(EXIT_FAILURE, "Failed to drop priviledges (setregid)");
	}

	if (setreuid(info.st_uid, info.st_uid) != 0) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Failed to drop priviledges (setreuid)");
		err(EXIT_FAILURE, "Failed to drop priviledges (setreuid)");
	}

	if (pw -> pw_dir) {
		setenv("HOME", pw -> pw_dir, 1);
	}
}

void ProcessManager::prepare_starter() {}

void ProcessManager::process_starter() {

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		Logger::getInstance().log(Logger::Verbosity::ERROR,
			"Process starter prctl error: %s",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	prepare_starter();

	

	while (runnable) {
		Logger::getInstance().log(Logger::Verbosity::INFO,
			"Process starter: waiting for command to start");

		Strings task;
		int res = task_bridge -> recv_strings(task);
		if (res == -1) {
			Logger::getInstance().log(Logger::Verbosity::ERROR,
				"Faield to recv task to start: %s",
				strerror(errno));
			continue;
		}
		Logger::getInstance().log(Logger::Verbosity::INFO,
			"Command: '%s'\tLog path: %s", task.str1.c_str(),
			task.str2.c_str());

		int stdoutFd =
			open((task.str2 + ".out").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
		int stderrFd =
			open((task.str2 + ".err").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);

		if (stdoutFd < 0 || stderrFd < 0) {
			Logger::getInstance().log(
				Logger::Verbosity::ERROR,
				"Failed to create stdin and stdout redirection: '%s'",
				strerror(errno));
			return;
		}

		start_process(task, stdoutFd, stderrFd);
	}
	Logger::getInstance().log(Logger::Verbosity::INFO,
		"Process starter: finished execution");
}