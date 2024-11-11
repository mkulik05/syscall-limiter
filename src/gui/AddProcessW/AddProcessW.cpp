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
#include <sys/syscall.h>

#include "../AddSyscallsW/AddSyscallsW.h"

QStringList syscalls = {"open", "close", "stat", "fstat", "lstat", "newfstatat", "access", "faccessat", "faccessat2", "mkdir", "mkdirat", "rmdir", "creat", "unlink", "unlinkat", "readlink", "readlinkat", "chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat", "chdir", "fchdir", "statfs", "fstatfs", "umount2", "openat", "openat2", "mknod", "mknodat", "utimensat", "futimesat", "name_to_handle_at", "open_by_handle_at", "read", "write", "getdents", "getdents64", "lseek", "fsync", "flock", "sendfile"};
std::unordered_map<QString, int> syscallMap = {{"open", SYS_open}, {"close", SYS_close}, {"stat", SYS_stat}, {"fstat", SYS_fstat}, {"lstat", SYS_lstat}, {"newfstatat", SYS_newfstatat}, {"access", SYS_access}, {"faccessat", SYS_faccessat}, {"faccessat2", SYS_faccessat2}, {"mkdir", SYS_mkdir}, {"mkdirat", SYS_mkdirat}, {"rmdir", SYS_rmdir}, {"creat", SYS_creat}, {"unlink", SYS_unlink}, {"unlinkat", SYS_unlinkat}, {"readlink", SYS_readlink}, {"readlinkat", SYS_readlinkat}, {"chmod", SYS_chmod}, {"fchmod", SYS_fchmod}, {"fchmodat", SYS_fchmodat}, {"chown", SYS_chown}, {"fchown", SYS_fchown}, {"lchown", SYS_lchown}, {"fchownat", SYS_fchownat}, {"chdir", SYS_chdir}, {"fchdir", SYS_fchdir}, {"statfs", SYS_statfs}, {"fstatfs", SYS_fstatfs}, {"umount2", SYS_umount2}, {"openat", SYS_openat}, {"openat2", SYS_openat2}, {"mknod", SYS_mknod}, {"mknodat", SYS_mknodat}, {"utimensat", SYS_utimensat}, {"futimesat", SYS_futimesat}, {"name_to_handle_at", SYS_name_to_handle_at}, {"open_by_handle_at", SYS_open_by_handle_at}, {"read", SYS_read}, {"write", SYS_write}, {"getdents", SYS_getdents}, {"getdents64", SYS_getdents64}, {"lseek", SYS_lseek}, {"fsync", SYS_fsync}, {"flock", SYS_flock}, {"sendfile", SYS_sendfile}};
std::unordered_map<int, QString> invertedSyscallMap = {{SYS_open, "open"}, {SYS_close, "close"}, {SYS_stat, "stat"}, {SYS_fstat, "fstat"}, {SYS_lstat, "lstat"}, {SYS_newfstatat, "newfstatat"}, {SYS_access, "access"}, {SYS_faccessat, "faccessat"}, {SYS_faccessat2, "faccessat2"}, {SYS_mkdir, "mkdir"}, {SYS_mkdirat, "mkdirat"}, {SYS_rmdir, "rmdir"}, {SYS_creat, "creat"}, {SYS_unlink, "unlink"}, {SYS_unlinkat, "unlinkat"}, {SYS_readlink, "readlink"}, {SYS_readlinkat, "readlinkat"}, {SYS_chmod, "chmod"}, {SYS_fchmod, "fchmod"}, {SYS_fchmodat, "fchmodat"}, {SYS_chown, "chown"}, {SYS_fchown, "fchown"}, {SYS_lchown, "lchown"}, {SYS_fchownat, "fchownat"}, {SYS_chdir, "chdir"}, {SYS_fchdir, "fchdir"}, {SYS_statfs, "statfs"}, {SYS_fstatfs, "fstatfs"}, {SYS_umount2, "umount2"}, {SYS_openat, "openat"}, {SYS_openat2, "openat2"}, {SYS_mknod, "mknod"}, {SYS_mknodat, "mknodat"}, {SYS_utimensat, "utimensat"}, {SYS_futimesat, "futimesat"}, {SYS_name_to_handle_at, "name_to_handle_at"}, {SYS_open_by_handle_at, "open_by_handle_at"}, {SYS_read, "read"}, {SYS_write, "write"}, {SYS_getdents, "getdents"}, {SYS_getdents64, "getdents64"}, {SYS_lseek, "lseek"}, {SYS_fsync, "fsync"}, {SYS_flock, "flock"}, {SYS_sendfile, "sendfile"}};

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

    formLayout->addRow("Process name:", progNameEdit);
    formLayout->addRow("Executable path:", progPathEdit);
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

AddProcessDialog::AddProcessDialog(QWidget *parent, QString name, QString path, QVector<RuleInfoGui> rules) : AddProcessDialog(parent)
{
    progNameEdit->setText(name);
    progPathEdit->setText(path);
    progPathEdit->setEnabled(false);
    for (int i = 0; i < rules.size(); i++)
    {
        QString message = "";
        for (const int &syscall : rules[i].syscalls)
        {
            message += invertedSyscallMap[syscall] + " ";
        }
        AddRuleRow(message);
        ruleTypeSels[i]->setCurrentIndex(rules[i].restrict_all ? 0 : 1);
        restrictPath[i]->setText(rules[i].path_info);
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
QVector<RuleInfoGui> AddProcessDialog::getRules() const
{
    QVector<RuleInfoGui> res = {};
    for (int row = 0; row < rulesTable->rowCount(); row++)
    {
        QString text = syscallsSels[row]->text();
        QVector<QString> words = text.split(" ", Qt::SkipEmptyParts).toVector();

        QVector<int> res_syscalls = {};
        for (int i = 0; i < words.size(); i++)
        {
            res_syscalls.append(syscallMap[words[i]]);
        }

        res.append({res_syscalls,
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
