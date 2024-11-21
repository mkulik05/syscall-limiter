#pragma once

#include <QApplication>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>
#include <QDialog>
#include <QLineEdit>
#include <QFormLayout>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QComboBox>
#include <QLabel>
#include <QStringList>
#include <QTextEdit>
#include <QVector>
#include <QString>
#include <unordered_map>

#include "configs/configs.h"
#include "../ProcessInfo.h"

struct HashableRule {
    std::string syscalls;
    bool ruleType;
    std::string path;
    
    HashableRule(const std::string &s, bool r, const std::string &p)
        : syscalls(s), ruleType(r), path(p) {}

    bool operator==(const HashableRule &other) const {
        return syscalls == other.syscalls &&
               ruleType == other.ruleType &&
               path == other.path;
    }
};

class AddProcessDialog : public QDialog {
Q_OBJECT
public:
    AddProcessDialog(QWidget *parent);
    AddProcessDialog(QWidget *parent, ProcessInfo& process_info);

    void addRule();

    int AddRuleRow(QString &message);

    QString getName() const;
    QString getProgPath() const;
    QVector<RuleInfoGui> getRules() const;
    int getMaxMem() const;
    int getMaxTime() const;

private slots:
    void checkAndAccept();
    
    void menuAddRule();
    void menuSaveRules();
    void menuImportRule(const std::string &ruleName);
   
private:
    void TableCellDoubleClicked(int row, int column);
    QMenu *importMenu;
    QLineEdit *progNameEdit;
    QLineEdit *progPathEdit;
    
    QLineEdit *progMaxMemEdit;
    QLineEdit *progMaxTimeEdit;
    std::vector<QLabel*> syscallsSels;      
    std::vector<QComboBox*> ruleTypeSels; 
    std::vector<QLineEdit*> restrictPathes; 
    QTableWidget *rulesTable;
    QStringList elements;    

    std::unordered_map<std::string, ConfigRules> all_rulesets;
                 
};