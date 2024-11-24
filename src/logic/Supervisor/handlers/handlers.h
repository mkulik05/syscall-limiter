#pragma once

#include <linux/seccomp.h>
#include <unordered_map>

#include "../../rules/rules.h"

typedef void (*MapHandler)(seccomp_notif*, seccomp_notif_resp*, int, std::vector<Rule>&);

void add_handlers(std::unordered_map<int, MapHandler>& map);
