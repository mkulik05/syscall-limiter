#pragma once
#include <QString>
#include <QVector>

struct RuleInfoGui {
    QVector<int> syscalls;
    bool restrict_all;
    QString path_info;
};

struct ProcessInfo {
    int pid;
    QString name;
    QString path;
    QVector<int> rules_ids;
    QVector<RuleInfoGui> rules;
    int maxMem;
    int maxTime;
    std::string log_path;
};