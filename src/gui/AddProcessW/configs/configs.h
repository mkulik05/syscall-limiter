#pragma once

#include <string>
#include <vector>
#include <sys/stat.h>
#include <unordered_map>
#include <dirent.h> 
#include <cstring>
#include <QDebug>

#include "../../../logic/Logger/Logger.h"

extern std::string conf_path;
extern std::string fold_name;

struct ConfigRuleData {
    std::vector<int> syscalls;
    bool restrictAny;
    std::string path;
};

struct ConfigRules {
    std::string name;
    std::vector<ConfigRuleData> rules;
};


int saveConfigRules(const ConfigRules& config, const std::string& filename);

std::unordered_map<std::string, ConfigRules> getAllRules();
