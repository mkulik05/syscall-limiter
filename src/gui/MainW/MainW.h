
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

#include "../AddProcessW/AddProcessW.h" 

struct ProcessInfo {
    int pid;
    QString name;
    QString path;
    QVector<int> rules_ids;
    QVector<RuleInfo> rules;
};

class MainW : public QWidget {
public:
    MainW();

private:
    QTableWidget *tableWidget;
    QVector<ProcessInfo> processes_info;

    void addElement();

    void editElement(QTableWidgetItem *item);
};