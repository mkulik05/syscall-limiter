#include "AddProcessW.h"
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QPushButton>
#include <QInputDialog>
#include <QComboBox>
#include <iostream>
#include <QMessageBox>
#include <QMouseEvent>
#include <QDebug>
#include <QScrollArea>
#include <QScrollBar>
#include <unordered_map>
#include <set>
#include <sys/syscall.h>
#include <QIntValidator>

#include "../AddSyscallsW/AddSyscallsW.h"

extern QStringList syscalls;
extern std::unordered_map<QString, int> syscallMap;
extern std::unordered_map<int, QString> invertedSyscallMap;
extern std::unordered_map<QString, QStringList> groups;

AddProcessDialog::AddProcessDialog(QWidget *parent) : QDialog(parent)
{
    setWindowTitle("Process Manager");
    setModal(true);
    syscallsSels = {};
    ruleTypeSels = {};
    restrictPath = {};

    QVBoxLayout *layout = new QVBoxLayout(this);

    QFormLayout *formLayout = new QFormLayout();
    progNameEdit = new QLineEdit(this);
    progPathEdit = new QLineEdit(this);

    progMaxMemEdit = new QLineEdit(this);
    progMaxTimeEdit = new QLineEdit(this);
    QIntValidator *intValidator = new QIntValidator(this);
    progMaxMemEdit->setValidator(intValidator);
    progMaxTimeEdit->setValidator(intValidator);

    formLayout->addRow("Process name:", progNameEdit);
    formLayout->addRow("Executable path:", progPathEdit);

    QHBoxLayout *hLayout = new QHBoxLayout();
    hLayout->addWidget(new QLabel("Maximum memory:"));
    hLayout->addWidget(progMaxMemEdit);
    hLayout->addSpacing(20); 
    hLayout->addWidget(new QLabel("Maximum CPU time:"));
    hLayout->addWidget(progMaxTimeEdit);

    // Add the horizontal layout to the form layout
    formLayout->addRow(hLayout);

    // Add the form layout to the main layout
    layout->addLayout(formLayout);

    QHBoxLayout *ruleLayout = new QHBoxLayout();
    QPushButton *addRuleButton = new QPushButton("Add Rule", this);

    connect(addRuleButton, &QPushButton::clicked, this, &AddProcessDialog::addRule);

    ruleLayout->addWidget(addRuleButton);
    layout->addLayout(ruleLayout);

    rulesTable = new QTableWidget(this);
    rulesTable->setColumnCount(3);
    rulesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    rulesTable->setHorizontalHeaderLabels(QStringList() << "Syscalls" << "Restrict type" << "Path");
    connect(rulesTable, &QTableWidget::cellDoubleClicked, this, &AddProcessDialog::TableCellDoubleClicked);
    layout->addWidget(rulesTable);

    QPushButton *saveButton = new QPushButton("Save", this);
    QPushButton *cancelButton = new QPushButton("Cancel", this);

    connect(saveButton, &QPushButton::clicked, this, &AddProcessDialog::accept);
    connect(cancelButton, &QPushButton::clicked, this, &AddProcessDialog::reject);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    resize(600, 300);
}

AddProcessDialog::AddProcessDialog(QWidget *parent, ProcessInfo& process_info) : AddProcessDialog(parent)
{
    progNameEdit->setText(process_info.name);
    progPathEdit->setText(process_info.path);
    progPathEdit->setEnabled(false);
    progMaxTimeEdit->setText(QString::number(process_info.maxTime));
    progMaxMemEdit->setText(QString::number(process_info.maxMem));
    for (int i = 0; i < process_info.rules.size(); i++)
    {
        QString message = "";
        for (const int &syscall : process_info.rules[i].syscalls)
        {
            message += invertedSyscallMap[syscall] + " ";
        }
        AddRuleRow(message);
        ruleTypeSels[i]->setCurrentIndex(process_info.rules[i].restrict_all ? 0 : 1);
        restrictPath[i]->setText(process_info.rules[i].path_info);
    }
}

void AddProcessDialog::TableCellDoubleClicked(int row, int column)
{
    if (column != 0)
    {
        return;
    }
    QString text = syscallsSels[row]->text();
    QVector<QString> words = text.split(" ", Qt::SkipEmptyParts).toVector();
    AddSyscallsW dialog(this, syscalls, words);
    if (dialog.exec() == QDialog::Accepted)
    {
        QVector<QString> selections = dialog.getSelections();
        QString message = "";
        for (const QString &selection : selections)
        {
            message += selection + " ";
        }
        qInfo() << message << "\n";
        syscallsSels[row]->setText(message);
    }
}

QString AddProcessDialog::getName() const { return progNameEdit->text(); }
QString AddProcessDialog::getProgPath() const { return progPathEdit->text(); }
int AddProcessDialog::getMaxMem() const {return progMaxMemEdit->text().toInt();}
int AddProcessDialog::getMaxTime() const {return progMaxTimeEdit->text().toInt();}
QVector<RuleInfoGui> AddProcessDialog::getRules() const
{
    QVector<RuleInfoGui> res = {};
    for (int row = 0; row < rulesTable->rowCount(); row++)
    {
        QString text = syscallsSels[row]->text();
        QVector<QString> words = text.split(" ", Qt::SkipEmptyParts).toVector();

        std::set<int> res_syscalls = {};
        for (int i = 0; i < words.size(); i++)
        {
            // check is it a group
            if (syscallMap.count(words[i]) == 0) {
                qInfo() << words[i] << "\n"; 
                for (int j = 0; j < groups[words[i]].size(); j++) {
                    res_syscalls.insert(syscallMap[groups[words[i]][j]]);
                }
            } else {
                res_syscalls.insert(syscallMap[words[i]]);
            }
            
        }

    
        QVector<int> qvec_res_syscalls = {};
        for (const int& value : res_syscalls) {
            qvec_res_syscalls.append(value);
        }
        res.append({qvec_res_syscalls,
                    ruleTypeSels[row]->currentIndex() == 0,
                    restrictPath[row]->text()});
    }
    return res;
}

void AddProcessDialog::addRule()
{

    AddSyscallsW dialog(this, syscalls);
    if (dialog.exec() == QDialog::Accepted)
    {
        QVector<QString> selections = dialog.getSelections();
        QString message = "";
        for (const QString &selection : selections)
        {
            message += selection + " ";
        }

        AddRuleRow(message);
    }
}

void AddProcessDialog::AddRuleRow(QString &message)
{
    QComboBox *ruleTypeSel = new QComboBox(this);
    ruleTypeSel->addItem("Any");
    ruleTypeSel->addItem("Path");
    this->ruleTypeSels.push_back(ruleTypeSel);

    int rowCount = rulesTable->rowCount();

    rulesTable->insertRow(rowCount);

    QScrollArea *scroll_area = new QScrollArea();
    QLabel *item = new QLabel(message);

    scroll_area->setWidget(item);
    scroll_area->setWidgetResizable(true);
    scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    item->setWordWrap(true);
    syscallsSels.push_back(item);

    rulesTable->setCellWidget(rowCount, 0, scroll_area);
    rulesTable->setCellWidget(rowCount, 1, ruleTypeSel);

    QLineEdit *path_item = new QLineEdit();
    restrictPath.push_back(path_item);
    path_item->setEnabled(false);
    connect(ruleTypeSel, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [path_item](int index)
            {
            if (index == 1) { // If "Path" is selected
                path_item->setEnabled(true); 
            } else {
                path_item->setEnabled(false);
                path_item->setText("");
            } });
    rulesTable->setCellWidget(rowCount, 2, path_item);
}
