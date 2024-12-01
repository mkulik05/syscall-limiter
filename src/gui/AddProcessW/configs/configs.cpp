#include "configs.h"
#include "../../../logic/Logger/Logger.h"
#include <string>
#include <unistd.h>
#include <cstdlib>

std::string conf_path = ".config";
std::string fold_name = "syscall-limiter";
bool inited_conf_path = false;

int init() {
    if (!inited_conf_path) {
        inited_conf_path = true;
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "failed to get such env");
            return -1;
        }
        Logger::getInstance().log(Logger::Verbosity::DEBUG, "Home folder: %s", homeDir);
        std::string str(homeDir);
        conf_path = str + "/" + conf_path;
    }
    struct stat buffer;
    bool conf_exists = stat(conf_path.c_str(), &buffer) == 0;

    if (!conf_exists) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Directory ~/.config doesn't exist, trying to create");
        if (mkdir(conf_path.c_str(), 0777) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to create ~/.config");
            return -1;
        }   
    }

    std::string path = conf_path + "/" + fold_name;
    bool prog_dir_exists = stat(path.c_str(), &buffer) == 0;
    if (!prog_dir_exists) {
        Logger::getInstance().log(Logger::Verbosity::INFO, "Directory ~/.config/syscall-limiter doesn't exist, trying to create");
        if (mkdir(path.c_str(), 0777) == -1) {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to create");
            return -1;
        }    
        
    }
    return 0;
}


int saveConfigRules(const ConfigRules& config, const std::string& filename) {
    if(init() == -1) return -1;

    std::ofstream ofs(conf_path + "/" + fold_name + "/" + filename, std::ios::binary);
    if (!ofs) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Error opening file for writing");
        return -1;
    }

    size_t nameLength = config.name.size();
    ofs.write(reinterpret_cast<const char*>(&nameLength), sizeof(nameLength));
    ofs.write(config.name.c_str(), nameLength);

    size_t rulesCount = config.rules.size();
    ofs.write(reinterpret_cast<const char*>(&rulesCount), sizeof(rulesCount));

    for (const auto& rule : config.rules) {

        size_t syscallCount = rule.syscalls.size();
        ofs.write(reinterpret_cast<const char*>(&syscallCount), sizeof(syscallCount));
        ofs.write(reinterpret_cast<const char*>(rule.syscalls.data()), syscallCount * sizeof(int));

        ofs.write(reinterpret_cast<const char*>(&rule.restrictAny), sizeof(rule.restrictAny));

        size_t pathLength = rule.path.size();
        ofs.write(reinterpret_cast<const char*>(&pathLength), sizeof(pathLength));
        ofs.write(rule.path.c_str(), pathLength);
    }

    ofs.close();

    return 0;
}

ConfigRules readConfigRules(const std::string& filename) {
    std::ifstream ifs(conf_path + "/" + fold_name + "/" + filename, std::ios::binary);
    ConfigRules config;

    if (!ifs) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Error opening file for reading: %s", strerror(errno));
        return config;
    }

    size_t nameLength = 0;
    ifs.read(reinterpret_cast<char*>(&nameLength), sizeof(nameLength));
    config.name.resize(nameLength);
    ifs.read(&config.name[0], nameLength);

    size_t rulesCount = 0;
    ifs.read(reinterpret_cast<char*>(&rulesCount), sizeof(rulesCount));
    config.rules.resize(rulesCount);

    for (auto& rule : config.rules) {
        size_t syscallCount = 0;
        ifs.read(reinterpret_cast<char*>(&syscallCount), sizeof(syscallCount));
        rule.syscalls.resize(syscallCount);
        ifs.read(reinterpret_cast<char*>(rule.syscalls.data()), syscallCount * sizeof(int));

        ifs.read(reinterpret_cast<char*>(&rule.restrictAny), sizeof(rule.restrictAny));

        size_t pathLength = 0;
        ifs.read(reinterpret_cast<char*>(&pathLength), sizeof(pathLength));
        rule.path.resize(pathLength);
        ifs.read(&rule.path[0], pathLength);
    }

    ifs.close();
    return config;
}

std::unordered_map<std::string, ConfigRules> getAllRules() {
    
    init();

    std::string path = conf_path + "/" + fold_name;
    DIR* dir = opendir(path.c_str());
    if (dir == nullptr) {
        Logger::getInstance().log(Logger::Verbosity::ERROR, "Error opening directory: %s", strerror(errno));
        return {};
    }

    std::vector<std::string> filenames;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            filenames.push_back(entry->d_name);
        }
    }

    std::unordered_map<std::string, ConfigRules> res = {};    

    for (int i = 0; i < filenames.size(); i++) {
        res[filenames[i]] = readConfigRules(filenames[i]);
    }

    return res; 
}


int deleteSavedRule(const  std::string& filename) {
    std::string base_path = conf_path + "/" + fold_name;
    return unlink((base_path + "/" + filename).c_str());
}