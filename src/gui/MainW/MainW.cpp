#include "MainW.h"
#include <QMessageBox>
#include "../AddProcessW/AddProcessW.h"
#include "../../logic/rules/rules.h"

MainW::MainW()
{

    process_manager = new ProcessManager();

    processes_info = {};
    setWindowTitle("Element List");

    QVBoxLayout *layout = new QVBoxLayout(this);

    tableWidget = new QTableWidget(this);
    tableWidget->setColumnCount(3);
    tableWidget->setHorizontalHeaderLabels(QStringList() << "Process name" << "PID" << "Status");

    tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    layout->addWidget(tableWidget);

    QPushButton *addButton = new QPushButton("Start new process", this);
    layout->addWidget(addButton);

    connect(addButton, &QPushButton::clicked, this, &MainW::addElement);
    connect(tableWidget, &QTableWidget::itemDoubleClicked, this, &MainW::editElement);

    resize(600, 300);
}

MainW::~MainW() {
    delete process_manager;
}

void MainW::addElement()
{
    AddProcessDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted)
    {
        QString name = dialog.getName();
        QString path = dialog.getProgPath();
        int maxMem = dialog.getMaxMem();
        int maxTime = dialog.getMaxTime();

        QVector<RuleInfoGui> rules = dialog.getRules();

        pid_t pid = process_manager->addProcess(path.toStdString());
        if (pid == -1) {
            QMessageBox::warning(this, "Unexpected error occurred", "Process have not started successfully", QMessageBox::Ok);
            return;
        }

        QVector<int> rules_ids = {};
        for (int i = 0; i < rules.size(); i++)
        {
            std::vector<int> syscalls(rules[i].syscalls.begin(), rules[i].syscalls.end());
            int id = process_manager->supervisor->addRule(pid, {0, rules[i].restrict_all ? DENY_ALWAYS : DENY_PATH_ACCESS, rules[i].path_info.toStdString()}, syscalls);
            rules_ids.append(id);
        }

        std::string memStr = "max";
        if (maxMem != 0) memStr = std::to_string(maxMem * 1024 * 1024);
        process_manager->setMemTime(pid, memStr, maxTime);

        process_manager->startProcess(pid);

        processes_info.append({pid, name, path, rules_ids, rules, maxMem, maxTime});

        int rowCount = tableWidget->rowCount();
        tableWidget->insertRow(rowCount);
        tableWidget->setItem(rowCount, 0, new QTableWidgetItem(name));
        tableWidget->setItem(rowCount, 1, new QTableWidgetItem(QString::number(pid)));
        tableWidget->setItem(rowCount, 2, new QTableWidgetItem("Running"));

        tableWidget->item(rowCount, 0)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        tableWidget->item(rowCount, 1)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
        tableWidget->item(rowCount, 2)->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
    }
}

void MainW::editElement(QTableWidgetItem *item)
{
    if (item)
    {
        int row = item->row();
        AddProcessDialog dialog(this, processes_info[row]);
        if (dialog.exec() == QDialog::Accepted)
        {
            QString name = dialog.getName();
            QVector<RuleInfoGui> new_rules = dialog.getRules();
            int maxMem = dialog.getMaxMem();
            int maxTime = dialog.getMaxTime();
            
            tableWidget->item(row, 0)->setText(name);

            processes_info[row].name = name;

            std::vector<std::pair<Rule, std::vector<int>>> new_rules_info = {};

            for (int i = 0; i < new_rules.size(); i++)
            {
                std::vector<int> syscalls(new_rules[i].syscalls.begin(), new_rules[i].syscalls.end());
                new_rules_info.push_back({{0, new_rules[i].restrict_all ? DENY_ALWAYS : DENY_PATH_ACCESS, new_rules[i].path_info.toStdString()}, syscalls});
            }

            std::vector<int> old_rules_ids(processes_info[row].rules_ids.begin(), processes_info[row].rules_ids.end()); 

            std::string memStr = "max";
            if (maxMem != 0) memStr = std::to_string(maxMem * 1024 * 1024);
            process_manager->setMemTime(processes_info[row].pid, memStr, maxTime);
            std::vector<int> rules_ids = process_manager->supervisor->updateRules(processes_info[row].pid, old_rules_ids, new_rules_info);
            processes_info[row].rules = new_rules;
            processes_info[row].rules_ids = QVector<int>(rules_ids.begin(), rules_ids.end());

        }
    }
}