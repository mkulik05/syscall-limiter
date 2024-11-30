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

#include "../../logic/ProcessManager/ProcessManager.h"
#include "../ProcessInfo.h"

class MainW : public QWidget {
Q_OBJECT

public:
    MainW();
    ~MainW();

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    int running_n;
    ProcessManager *process_manager;
    QTableWidget *tableWidget;
    QVector<ProcessInfo> processes_info;

    void addElement();

    void editElement(QTableWidgetItem *item);
};