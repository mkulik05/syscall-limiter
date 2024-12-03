#include "AddProcessW.h"
#include <QVBoxLayout>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QPushButton>
#include <QInputDialog>
#include <QComboBox>
#include <QMessageBox>
#include <QMouseEvent>
#include <QDebug>
#include <QScrollArea>
#include <QScrollBar>
#include <unordered_map>
#include <set>
#include <sys/syscall.h>
#include <QIntValidator>
#include <QMenu>
#include <QMenuBar>
#include "../../logic/Logger/Logger.h"

#include "../AddSyscallsW/AddSyscallsW.h"

extern QStringList syscalls;
extern std::unordered_map<QString, int> syscallMap;
extern std::unordered_map<int, QString> invertedSyscallMap;

QString INP_ERROR_STYLES = "background-color: #ffcccc;";

AddProcessDialog::AddProcessDialog(QWidget *parent) : QDialog(parent)
{

    setWindowTitle("Process Manager");
    setModal(true);
    syscallsSels = {};
    ruleTypeSels = {};
    restrictPathes = {};

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins({10, 0, 10, 0});

    QMenuBar *menuBar = new QMenuBar(this);
    menuBar->setBaseSize(100, 100);
    QMenu *rulesMenu = menuBar->addMenu("Rules");

    QAction *addRuleAction = new QAction("Add", this);
    connect(addRuleAction, &QAction::triggered, this, &AddProcessDialog::addRule);
    rulesMenu->addAction(addRuleAction);

    QAction *saveRulesAction = new QAction("Save", this);
    connect(saveRulesAction, &QAction::triggered, this, &AddProcessDialog::menuSaveRules);
    rulesMenu->addAction(saveRulesAction);

    all_rulesets = getAllRules();

    importMenu = rulesMenu->addMenu("Import");

    deleteMenu = rulesMenu->addMenu("Delete");

    for (std::pair<std::string, ConfigRules> ruleset : all_rulesets)
    {
        QAction *importAction = new QAction(QString::fromStdString(ruleset.second.name), this);
        connect(importAction, &QAction::triggered, [this, ruleset]()
                { menuImportRule(ruleset.first); });
        
        importAction->setData(QString::fromStdString(ruleset.first)); 
        importMenu->addAction(importAction);

        QAction *deleteAction = new QAction(QString::fromStdString(ruleset.second.name), this);
        connect(deleteAction, &QAction::triggered, [this, ruleset]()
                { menuDeleteRule(ruleset.first); });
        deleteAction->setData(QString::fromStdString(ruleset.first));                
        deleteMenu->addAction(deleteAction);
    }

    layout->setMenuBar(menuBar);

    layout->addSpacing(20);

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
    connect(progPathEdit, &QLineEdit::textChanged, this, [=](const QString &val)
            {
        if (val.isEmpty()) {
            progPathEdit->setStyleSheet(INP_ERROR_STYLES);
        } else {
            progPathEdit->setStyleSheet("");
        } });

    layout->addLayout(formLayout);

    layout->addSpacing(12);
    QFrame *sep = new QFrame();
    sep->setFrameShape(QFrame::HLine);
    sep->setFrameShadow(QFrame::Sunken);
    layout->addWidget(sep);
    layout->addSpacing(8);

    QHBoxLayout *hLayout = new QHBoxLayout();
    QVBoxLayout *vLayout1 = new QVBoxLayout();
    QVBoxLayout *vLayout2 = new QVBoxLayout();
    vLayout1->addWidget(new QLabel("Maximum memory:"));
    vLayout1->addWidget(progMaxMemEdit);
    hLayout->addLayout(vLayout1);
    hLayout->addSpacing(20);
    vLayout2->addWidget(new QLabel("Maximum CPU time:"));
    vLayout2->addWidget(progMaxTimeEdit);
    hLayout->addLayout(vLayout2);

    layout->addLayout(hLayout);

    layout->addSpacing(20);

    QPushButton *addRuleButton = new QPushButton("Add Rule", this);
    connect(addRuleButton, &QPushButton::clicked, this, &AddProcessDialog::addRule);
    layout->addWidget(addRuleButton);

    layout->addSpacing(10);

    rulesTable = new QTableWidget(this);
    rulesTable->setColumnCount(4);

    rulesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    rulesTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Fixed);

    rulesTable->setHorizontalHeaderLabels(QStringList() << "Syscalls" << "Restrict type" << "Path" << "");
    rulesTable->setColumnWidth(3, 50);
    connect(rulesTable, &QTableWidget::cellDoubleClicked, this, &AddProcessDialog::TableCellDoubleClicked);

    connect(rulesTable, &QTableWidget::cellClicked, [&](int row, int column)
            {
        if (column == 3) {
            syscallsSels.erase(syscallsSels.begin() + row);
            ruleTypeSels.erase(ruleTypeSels.begin() + row);
            restrictPathes.erase(restrictPathes.begin() + row);
            rulesTable->removeRow(row);
        } });

    layout->addWidget(rulesTable);

    QPushButton *saveButton = new QPushButton("Save", this);
    QPushButton *cancelButton = new QPushButton("Cancel", this);

    connect(saveButton, &QPushButton::clicked, this, &AddProcessDialog::checkAndAccept);
    connect(cancelButton, &QPushButton::clicked, this, &AddProcessDialog::reject);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    layout->addSpacing(10);

    resize(600, 600);
}

AddProcessDialog::AddProcessDialog(QWidget *parent, ProcessInfo &process_info) : AddProcessDialog(parent)
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
        int row = AddRuleRow(message);
        ruleTypeSels[row]->setCurrentIndex(process_info.rules[i].restrict_all ? 0 : 1);
        restrictPathes[row]->setText(process_info.rules[i].path_info);
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
        syscallsSels[row]->setText(message);
        if (selections.size() != 0)
        {
            syscallsSels[row]->setStyleSheet("");
        }
        else
        {
            syscallsSels[row]->setStyleSheet(INP_ERROR_STYLES);
        }
    }
}

QString AddProcessDialog::getName() const { return progNameEdit->text(); }
QString AddProcessDialog::getProgPath() const { return progPathEdit->text(); }
int AddProcessDialog::getMaxMem() const { return progMaxMemEdit->text().toInt(); }
int AddProcessDialog::getMaxTime() const { return progMaxTimeEdit->text().toInt(); }

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

        QString str = restrictPathes[row]->text();


        if (str.endsWith('/')) {
            str.chop(1); 
        }

        res.append({res_syscalls,
                    ruleTypeSels[row]->currentIndex() == 0,
                    str});
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

int AddProcessDialog::AddRuleRow(QString &message)
{
    QComboBox *ruleTypeSel = new QComboBox(this);
    ruleTypeSel->addItem("Any");
    ruleTypeSel->addItem("Path");
    ruleTypeSel->setStyleSheet("background: transparent; border: none; padding-left: 5px;");
    this->ruleTypeSels.push_back(ruleTypeSel);

    int rowCount = rulesTable->rowCount();

    rulesTable->insertRow(rowCount);

    QScrollArea *scroll_area = new QScrollArea();
    QLabel *syscallsLabel = new QLabel(message);

    syscallsLabel->setStyleSheet("padding-left: 5px;");

    scroll_area->setWidget(syscallsLabel);
    scroll_area->setWidgetResizable(true);
    scroll_area->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scroll_area->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    syscallsLabel->setWordWrap(true);
    syscallsSels.push_back(syscallsLabel);

    rulesTable->setCellWidget(rowCount, 0, scroll_area);
    rulesTable->setCellWidget(rowCount, 1, ruleTypeSel);

    QLineEdit *path_item = new QLineEdit();
    restrictPathes.push_back(path_item);
    path_item->setEnabled(false);
    connect(ruleTypeSel, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [path_item](int index)
            {
            if (index == 1) { // If "Path" is selected
                path_item->setEnabled(true); 
            } else {
                path_item->setStyleSheet("");
                path_item->setEnabled(false);
                path_item->setText("");
            } });
    rulesTable->setCellWidget(rowCount, 2, path_item);

    connect(path_item, &QLineEdit::textChanged, this, [=](const QString &val)
            {
        if ((ruleTypeSel->currentIndex() == 1) && val.isEmpty()) {
            path_item->setStyleSheet(INP_ERROR_STYLES);
        } else {
            path_item->setStyleSheet("");
        } });

    QTableWidgetItem *table_item = new QTableWidgetItem("X");
    table_item->setTextAlignment(Qt::AlignCenter);
    table_item->setForeground(Qt::red);
    table_item->setFlags(Qt::ItemIsEnabled);

    rulesTable->setItem(rowCount, 3, table_item);

    return rowCount;
}

void AddProcessDialog::checkAndAccept()
{
    bool valid = true;

    if (progPathEdit->text().isEmpty())
    {
        progPathEdit->setStyleSheet(INP_ERROR_STYLES);
        valid = false;
    }

    for (int i = 0; i < rulesTable->rowCount(); i++)
    {
        if (ruleTypeSels[i]->currentIndex() == 1 && restrictPathes[i]->text().isEmpty())
        {
            restrictPathes[i]->setStyleSheet(INP_ERROR_STYLES);
            valid = false;
        }

        if (syscallsSels[i]->text().isEmpty())
        {
            syscallsSels[i]->setStyleSheet(INP_ERROR_STYLES);
            valid = false;
        }
    }

    if (!valid)
    {
        QMessageBox::warning(this, "Warning", "Please fill in the highlighted fields.");
    }
    else
    {
        accept();
    }
}

void AddProcessDialog::menuAddRule()
{
    qDebug("Add Rule clicked");
}

void AddProcessDialog::menuSaveRules()
{
    int n = rulesTable->rowCount();

    if (n == 0) {
        QMessageBox::information(this, "Saving failed", "No rules to save");
        return;
    }

    bool ok;
    QString name = QInputDialog::getText(this, tr("Save Rules"),
                                         tr("Enter rule name:"), QLineEdit::Normal,
                                         "", &ok);
    if (ok && !name.isEmpty())
    {

        auto now = std::chrono::system_clock::now();
        std::time_t unix_time = std::chrono::system_clock::to_time_t(now);

        std::vector<ConfigRuleData> ruleData = {};

        for (int row = 0; row < rulesTable->rowCount(); row++)
        {
            QString text = syscallsSels[row]->text();
            QVector<QString> words = text.split(" ", Qt::SkipEmptyParts).toVector();

            std::set<int> res_syscalls = {};
            for (int i = 0; i < words.size(); i++)
            {
                res_syscalls.insert(syscallMap[words[i]]);
            }

            std::vector<int> qvec_res_syscalls = {};
            for (const int &value : res_syscalls)
            {
                qvec_res_syscalls.push_back(value);
            }

            ruleData.push_back({qvec_res_syscalls, ruleTypeSels[row]->currentIndex() == 0, restrictPathes[row]->text().toStdString()});
        }
        ConfigRules resConfig = {name.toStdString(), ruleData};
        int r = saveConfigRules(resConfig, std::to_string(unix_time));
        if (r == -1)
        {
            Logger::getInstance().log(Logger::Verbosity::ERROR, "Failed to save rule");
        }
        else
        {
            QAction *importAction = new QAction(name, this);
            connect(importAction, &QAction::triggered, [this, unix_time]()
                    { menuImportRule(std::to_string(unix_time)); });
            importMenu->addAction(importAction);

            QAction *deleteAction = new QAction(name, this);
            connect(deleteAction, &QAction::triggered, [this, unix_time]()
                    { menuDeleteRule(std::to_string(unix_time)); });
            deleteMenu->addAction(deleteAction);

            all_rulesets[std::to_string(unix_time)] = resConfig;
        }
    }
}

namespace std
{
    template <>
    struct hash<HashableRule>
    {
        std::size_t operator()(const HashableRule &rule) const
        {
            std::size_t h1 = std::hash<std::string>()(rule.syscalls);
            std::size_t h2 = std::hash<bool>()(rule.ruleType);
            std::size_t h3 = std::hash<std::string>()(rule.path);

            return h1 ^ (h2 << 1) ^ (h3 << 2);
        }
    };
}

void AddProcessDialog::menuImportRule(const std::string &ruleIDStr)
{
    std::unordered_map<HashableRule, bool> existing_rules;

    for (int i = 0; i < rulesTable->rowCount(); i++)
    {
        HashableRule rule(syscallsSels[i]->text().toStdString(), ruleTypeSels[i]->currentIndex() == 0, restrictPathes[i]->text().toStdString());
        existing_rules.insert({rule, 0});
    }

    int i = 0;
    for (const ConfigRuleData &rule : all_rulesets[ruleIDStr].rules)
    {
        QString message = "";
        for (const int &syscall : rule.syscalls)
        {
            message += invertedSyscallMap[syscall] + " ";
        }

        HashableRule rule2add(message.toStdString(), rule.restrictAny, rule.path);

        if (existing_rules.count(rule2add) != 0)
            continue;

        int row = AddRuleRow(message);
        ruleTypeSels[row]->setCurrentIndex(rule.restrictAny ? 0 : 1);
        restrictPathes[row]->setText(QString::fromStdString(rule.path));
        i++;
    }
    QMessageBox::information(this, "Importing finished", "Imported " + QString::number(i) + " rules");
}

void AddProcessDialog::menuDeleteRule(const std::string &ruleIDStr)
{
    int rule_n = all_rulesets[ruleIDStr].rules.size();
    QString message = QString("Are you sure you want to delete this ruleset?\nIt contains %1 rule(s)").arg(rule_n);

    int reply = QMessageBox::question(this, "Confirm Deletion", message,
                                  QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::No) {
        return;
    }

    
    for (QAction *action : deleteMenu->actions()) {
        if (action->data().toString().toStdString() == ruleIDStr) {
            deleteMenu->removeAction(action); 
            delete action;
            break;
        }
    }

    for (QAction *action : importMenu->actions()) {
        if (action->data().toString().toStdString() == ruleIDStr) {
            importMenu->removeAction(action); 
            delete action;
            break;
        }
    }

    all_rulesets.erase(ruleIDStr);
    deleteSavedRule(ruleIDStr);
}