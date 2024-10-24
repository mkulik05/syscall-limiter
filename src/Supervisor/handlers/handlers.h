#pragma once

#include <linux/seccomp.h>

#include "../../rules/rules.h"

typedef void (*MapHandler)(seccomp_notif*, seccomp_notif_resp*, int, std::vector<Rule>&);

void add_handlers(std::map<int, MapHandler>& map);
