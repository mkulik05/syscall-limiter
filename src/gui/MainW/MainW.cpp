#include "MainW.h"
#include "../AddProcessW/AddProcessW.h"

MainW::MainW() {
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


void MainW::addElement() {
    AddProcessDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted) {
        QString name = dialog.getName();
        QString path = dialog.getProgPath();
        int pid = 1200;
        QVector<RuleInfo> rules = dialog.getRules();
        
        QVector<int> rules_ids = {};
        for (int i = 0; i < rules.size(); i++) {
            rules_ids.append(i);
        }

        processes_info.append({pid, name, path, rules_ids, rules});
        
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

void MainW::editElement(QTableWidgetItem *item) {
    if (item) {
        int row = item->row();
        AddProcessDialog dialog(this, processes_info[row].name, processes_info[row].path, processes_info[row].rules);
        if (dialog.exec() == QDialog::Accepted) {
            QString name = dialog.getName();
            QVector<RuleInfo> new_rules = dialog.getRules();
            tableWidget->item(row, 0)->setText(name);
            processes_info[row].name = name;

            QVector<int> rules_ids = {};
            for (int i = 0; i < new_rules.size(); i++) {

            }
            processes_info[row].rules = new_rules;
        }
    }
}